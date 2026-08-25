package impersonate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type user struct {
	ID     uuid.UUID
	Active bool
	Name   string
}

type fakeStore struct {
	actor         *user
	target        *user
	impersonateID *uuid.UUID
	sessionErr    error
	userErr       error
	cleared       int
}

func (f *fakeStore) SessionFromToken(context.Context, string) (*user, *uuid.UUID, error) {
	return f.actor, f.impersonateID, f.sessionErr
}

func (f *fakeStore) UserByID(context.Context, uuid.UUID) (*user, error) {
	return f.target, f.userErr
}

func (f *fakeStore) ClearImpersonation(context.Context, string) error {
	f.cleared++
	return nil
}

func request(store *fakeStore, cookie bool) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if cookie {
		c.Request.AddCookie(&http.Cookie{Name: "sess", Value: "token"})
	}
	h := Session("sess", store, func(u *user) bool { return u.Active })
	h(c)
	return c
}

func TestSessionNoCookie(t *testing.T) {
	c := request(&fakeStore{actor: &user{Name: "a"}}, false)
	if User[user](c) != nil || Actor[user](c) != nil || IsImpersonating(c) {
		t.Fatal("expected empty session")
	}
}

func TestSessionActorOnly(t *testing.T) {
	actor := &user{ID: uuid.New(), Active: true, Name: "actor"}
	c := request(&fakeStore{actor: actor}, true)
	if User[user](c) != actor {
		t.Fatal("user should be actor")
	}
	if Actor[user](c) != actor {
		t.Fatal("actor mismatch")
	}
	if IsImpersonating(c) {
		t.Fatal("not impersonating")
	}
}

func TestSessionImpersonating(t *testing.T) {
	actor := &user{ID: uuid.New(), Active: true, Name: "actor"}
	target := &user{ID: uuid.New(), Active: true, Name: "target"}
	id := target.ID
	c := request(&fakeStore{actor: actor, target: target, impersonateID: &id}, true)
	if User[user](c) != target {
		t.Fatal("user should be target")
	}
	if Actor[user](c) != actor {
		t.Fatal("actor should stay the session owner")
	}
	if !IsImpersonating(c) {
		t.Fatal("expected impersonating")
	}
}

func TestSessionInactiveTargetClears(t *testing.T) {
	actor := &user{ID: uuid.New(), Active: true, Name: "actor"}
	target := &user{ID: uuid.New(), Active: false, Name: "target"}
	id := target.ID
	store := &fakeStore{actor: actor, target: target, impersonateID: &id}
	c := request(store, true)
	if store.cleared != 1 {
		t.Fatalf("cleared=%d", store.cleared)
	}
	if User[user](c) != actor {
		t.Fatal("should fall back to actor")
	}
	if IsImpersonating(c) {
		t.Fatal("should not impersonate inactive user")
	}
}

func TestSessionMissingTargetClears(t *testing.T) {
	actor := &user{ID: uuid.New(), Active: true, Name: "actor"}
	id := uuid.New()
	store := &fakeStore{actor: actor, impersonateID: &id, userErr: errors.New("gone")}
	c := request(store, true)
	if store.cleared != 1 {
		t.Fatalf("cleared=%d", store.cleared)
	}
	if User[user](c) != actor || IsImpersonating(c) {
		t.Fatal("missing target should fall back")
	}
}

func TestSessionBadToken(t *testing.T) {
	c := request(&fakeStore{sessionErr: errors.New("nope")}, true)
	if User[user](c) != nil {
		t.Fatal("invalid session should be ignored")
	}
}
