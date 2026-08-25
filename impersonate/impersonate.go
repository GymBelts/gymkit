package impersonate

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	UserKey          = "user"
	ActorKey         = "actor"
	ImpersonatingKey = "impersonating"
)

type Store[U any] interface {
	SessionFromToken(ctx context.Context, token string) (actor *U, impersonateID *uuid.UUID, err error)
	UserByID(ctx context.Context, id uuid.UUID) (*U, error)
	ClearImpersonation(ctx context.Context, token string) error
}

func Session[U any](cookieName string, store Store[U], active func(*U) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(cookieName)
		if err != nil || token == "" {
			c.Next()
			return
		}
		actor, impersonateID, err := store.SessionFromToken(c.Request.Context(), token)
		if err != nil {
			c.Next()
			return
		}
		c.Set(ActorKey, actor)
		if impersonateID != nil {
			target, err := store.UserByID(c.Request.Context(), *impersonateID)
			if err != nil || target == nil || (active != nil && !active(target)) {
				_ = store.ClearImpersonation(c.Request.Context(), token)
				c.Set(UserKey, actor)
				c.Next()
				return
			}
			c.Set(UserKey, target)
			c.Set(ImpersonatingKey, true)
			c.Next()
			return
		}
		c.Set(UserKey, actor)
		c.Next()
	}
}

func User[U any](c *gin.Context) *U {
	return value[U](c, UserKey)
}

func Actor[U any](c *gin.Context) *U {
	if u := value[U](c, ActorKey); u != nil {
		return u
	}
	return User[U](c)
}

func IsImpersonating(c *gin.Context) bool {
	v, ok := c.Get(ImpersonatingKey)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func value[U any](c *gin.Context, key string) *U {
	v, ok := c.Get(key)
	if !ok {
		return nil
	}
	u, _ := v.(*U)
	return u
}
