package oidc

import (
	"strings"
	"testing"
)

func TestPKCEChallengeRFC7636(t *testing.T) {
	// RFC 7636 Appendix B
	got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRandomURLString(t *testing.T) {
	a, err := RandomURLString(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomURLString(32)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected unique values")
	}
	if strings.ContainsAny(a, "+/") {
		t.Fatalf("not url-safe: %q", a)
	}
}

func TestAuthorizeURLScopes(t *testing.T) {
	c := New(Config{
		Issuer:      "https://auth.example",
		ClientID:    "amp",
		RedirectURL: "https://amp.example/auth/callback",
		Scopes:      []string{"openid", "profile", "roles.write"},
	})
	u := c.AuthorizeURL("st", "n", "ch")
	if !strings.Contains(u, "scope=openid+profile+roles.write") && !strings.Contains(u, "scope=openid%20profile%20roles.write") {
		t.Fatalf("scopes missing from %s", u)
	}
	if !strings.Contains(u, "https://auth.example/oauth/authorize?") {
		t.Fatalf("issuer path: %s", u)
	}
}

func TestLogoutURL(t *testing.T) {
	c := New(Config{
		Issuer:      "https://auth.example",
		RedirectURL: "https://amp.example/auth/callback",
	})
	got := c.LogoutURL()
	want := "https://auth.example/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Famp.example%2F"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
