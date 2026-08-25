package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Config struct {
	Issuer       string
	InternalURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type Client struct {
	issuer   string
	internal string
	clientID string
	secret   string
	redirect string
	scopes   []string
	http     *http.Client
	mu       sync.Mutex
	jwks     jwksDoc
	jwksAt   time.Time
}

type Claims struct {
	Subject  string
	Email    string
	Name     string
	Nickname string
	Role     string
	Gym      string
}

func New(cfg Config) *Client {
	internal := cfg.InternalURL
	if internal == "" {
		internal = cfg.Issuer
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	return &Client{
		issuer:   strings.TrimRight(cfg.Issuer, "/"),
		internal: strings.TrimRight(internal, "/"),
		clientID: cfg.ClientID,
		secret:   cfg.ClientSecret,
		redirect: cfg.RedirectURL,
		scopes:   scopes,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) AuthorizeURL(state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirect)
	q.Set("scope", strings.Join(c.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return c.issuer + "/oauth/authorize?" + q.Encode()
}

func (c *Client) LogoutURL() string {
	postLogout := strings.TrimRight(c.redirect, "/auth/callback") + "/"
	if i := strings.Index(c.redirect, "/auth/callback"); i > 0 {
		postLogout = c.redirect[:i] + "/"
	}
	q := url.Values{}
	q.Set("post_logout_redirect_uri", postLogout)
	return c.issuer + "/oauth/logout?" + q.Encode()
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
}

func (c *Client) Exchange(code, verifier string) (Claims, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirect)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.secret)
	form.Set("code_verifier", verifier)
	var tr tokenResp
	if err := c.postToken(form, &tr); err != nil {
		return Claims{}, "", err
	}
	claims, err := c.parseIDToken(tr.IDToken)
	if err != nil {
		return Claims{}, "", err
	}
	return claims, tr.RefreshToken, nil
}

func (c *Client) Refresh(refreshToken string) (Claims, string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.secret)
	var tr tokenResp
	if err := c.postToken(form, &tr); err != nil {
		return Claims{}, "", err
	}
	next := tr.RefreshToken
	if next == "" {
		next = refreshToken
	}
	if tr.IDToken == "" {
		return Claims{}, next, nil
	}
	claims, err := c.parseIDToken(tr.IDToken)
	if err != nil {
		return Claims{}, "", err
	}
	return claims, next, nil
}

func (c *Client) postToken(form url.Values, out *tokenResp) error {
	req, err := http.NewRequest(http.MethodPost, c.internal+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint %s: %s", resp.Status, body)
	}
	return json.Unmarshal(body, out)
}

type idClaims struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
	Gym      string `json:"gym"`
	jwt.RegisteredClaims
}

func (c *Client) parseIDToken(raw string) (Claims, error) {
	var empty Claims
	keyFn := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return c.keyFor(kid)
	}
	var ic idClaims
	_, err := jwt.ParseWithClaims(raw, &ic, keyFn,
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.clientID),
	)
	if err != nil {
		return empty, err
	}
	if ic.Subject == "" {
		return empty, fmt.Errorf("invalid sub")
	}
	gym := ic.Gym
	if gym == "" {
		gym = "gymbelts"
	}
	return Claims{
		Subject:  ic.Subject,
		Email:    ic.Email,
		Name:     ic.Name,
		Nickname: ic.Nickname,
		Role:     ic.Role,
		Gym:      gym,
	}, nil
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

func (c *Client) keyFor(kid string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.jwksAt) > 10*time.Minute || len(c.jwks.Keys) == 0 {
		resp, err := c.http.Get(c.internal + "/oauth/jwks")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&c.jwks); err != nil {
			return nil, err
		}
		c.jwksAt = time.Now()
	}
	for _, k := range c.jwks.Keys {
		if k.Kid == kid || kid == "" {
			return parseRSAPublic(k)
		}
	}
	return nil, fmt.Errorf("unknown kid")
}

func parseRSAPublic(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	var e int
	for _, b := range eb {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func RandomURLString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (c *Client) AccessToken(refreshToken string) (access, nextRefresh string, err error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.secret)
	var tr tokenResp
	if err := c.postToken(form, &tr); err != nil {
		return "", "", err
	}
	next := tr.RefreshToken
	if next == "" {
		next = refreshToken
	}
	if tr.AccessToken == "" {
		return "", "", fmt.Errorf("no access token")
	}
	return tr.AccessToken, next, nil
}

type CreatedUser struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Role  string    `json:"role"`
}

type createUserResp struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (c *Client) CreateAppUser(slug, accessToken, email, name, nickname, password, role string) (CreatedUser, error) {
	var empty CreatedUser
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"name":     name,
		"nickname": nickname,
		"password": password,
		"role":     role,
	})
	req, err := http.NewRequest(http.MethodPost, c.appUsersURL(slug, ""), strings.NewReader(string(body)))
	if err != nil {
		return empty, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return empty, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		return empty, fmt.Errorf("email already exists in GymAuth")
	}
	if resp.StatusCode >= 300 {
		return empty, fmt.Errorf("create user: %s %s", resp.Status, b)
	}
	var out createUserResp
	if err := json.Unmarshal(b, &out); err != nil {
		return empty, err
	}
	id, err := uuid.Parse(out.ID)
	if err != nil {
		return empty, fmt.Errorf("create user: invalid id")
	}
	return CreatedUser{ID: id, Email: out.Email, Role: out.Role}, nil
}

type PatchUser struct {
	Email    *string
	Name     *string
	Nickname *string
	Password *string
	Active   *bool
}

func (c *Client) PatchAppUser(slug, accessToken string, authUserID uuid.UUID, patch PatchUser) error {
	body := map[string]any{}
	if patch.Email != nil {
		body["email"] = *patch.Email
	}
	if patch.Name != nil {
		body["name"] = *patch.Name
	}
	if patch.Nickname != nil {
		body["nickname"] = *patch.Nickname
	}
	if patch.Password != nil {
		body["password"] = *patch.Password
	}
	if patch.Active != nil {
		body["active"] = *patch.Active
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPatch, c.appUsersURL(slug, authUserID.String()), strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user: %s %s", resp.Status, b)
	}
	return nil
}

func (c *Client) SetAppRole(slug string, authUserID uuid.UUID, role, accessToken string) error {
	body, _ := json.Marshal(map[string]string{"role": role})
	req, err := http.NewRequest(http.MethodPut, c.appUsersURL(slug, authUserID.String())+"/role", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set role: %s %s", resp.Status, b)
	}
	return nil
}

func (c *Client) appUsersURL(slug, id string) string {
	base := c.internal + "/api/v1/apps/" + url.PathEscape(slug) + "/users"
	if id == "" {
		return base
	}
	return base + "/" + url.PathEscape(id)
}
