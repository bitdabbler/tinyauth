package tinyauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/bitdabbler/acrypt"
)

// Middleware provides token-based auth protection for routes. If it incurs an
// error, it calls the MiddlewareErrorHandler to process it. This middleware is
// compatible with the standard library API.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := extractBearerToken(r.Header.Get(authHeaderKey))
		if err != nil {
			MiddlewareErrorHandler(w, r, NewErrorBadInput(
				"tinyauth middleware",
				err,
			))
			return
		}
		t, err := g.decodeToken([]byte(raw))
		if err != nil {
			MiddlewareErrorHandler(w, r, NewErrorBadInput(
				"tinyauth middleware",
				err,
			))
			return
		}
		if err := g.check(t); err != nil {
			MiddlewareErrorHandler(w, r, NewErrorAuthFailed(
				"tinyauth middleware",
				err,
			))
			return
		}
		r, err = g.requestWithToken(w, r, t)
		if err != nil {
			MiddlewareErrorHandler(w, r, NewErrorInternal(
				"tinyauth middleware",
				err,
			))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MiddlewareErrorHandler processes errors thrown by the middleware. It is
// exposed so that users of the library can replace it to provide their own
// custom error handling.
var MiddlewareErrorHandler = func(w http.ResponseWriter, r *http.Request, err *Error) {
	log.Printf("auth failed: %v", err)
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}

// LoginHandler authenticates a user. If successful, it puts the auth token into
// the Authorization header and then calls the LoginSuccessHandler. If the user
// cannot be authenticated, it calls the LoginErrorHandler. The inbound POST
// request must contain: `{"user_id": "alice", password:"secret"}`.
func (g *Guard) LoginHandler() http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		loginForm := struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
		}{}
		sBytes, err := io.ReadAll(r.Body)
		if err != nil {
			LoginErrorHandler(w, r, NewErrorInternal(
				"failed to read request body",
				err,
			))
			return
		}
		if err := json.Unmarshal(sBytes, &loginForm); err != nil {
			LoginErrorHandler(w, r, NewErrorBadInput(
				"failed to parse JSON login form",
				err,
			))
			return
		}
		if len(loginForm.UserID) == 0 || len(loginForm.Password) == 0 {
			LoginErrorHandler(w, r, NewErrorBadInput(
				"invalid login parameters",
				errors.New("user_id and password required"),
			))
			return
		}
		u, h, err := g.db.GetAuthable(loginForm.UserID, true)
		if err != nil {
			LoginErrorHandler(w, r, NewErrorAuthFailed(
				"invalid login parameters",
				err,
			))
			return
		}
		err = acrypt.CompareHashAndPassword(h, []byte(loginForm.Password))
		if err != nil {
			LoginErrorHandler(w, r, NewErrorAuthFailed(
				"invalid login parameters",
				err,
			))
			return
		}

		t := newToken(u)
		if err = g.writeAuthHeader(w, t); err != nil {
			LoginErrorHandler(w, r, NewErrorInternal(
				"failed to write auth header",
				err,
			))
			return
		}
		LoginSuccessHandler(w, r)
	}
	return http.HandlerFunc(f)
}

// LoginSuccessHandler returns status 200 with text "login successful". It is
// exposed so that users can replace it with custom logic if desired.
var LoginSuccessHandler = func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("login successful"))
}

// LoginErrorHandler is called if the user cannot be authenticated. It is
// exposed so that users can replace it with custom logic if desired.
var LoginErrorHandler = func(w http.ResponseWriter, r *http.Request, err *Error) {
	log.Println(err.Error())
	switch err.ErrType {
	case ErrBadInput:
		http.Error(w, err.Msg, http.StatusBadRequest)
	case ErrInternal:
		http.Error(w, err.Msg, http.StatusInternalServerError)
	case ErrAuthFailed:
		http.Error(w, err.Msg, http.StatusUnauthorized)
	}
}

// LogoutHandler returns an http.Handler that is used to add the session to a
// blacklist of cancelled sessions, to prevent further auto-refresh. If success-
// ful, it calls the LogoutSuccessHandler, otherwise it calls the
// LogoutErrorHandler.
func (g *Guard) LogoutHandler() http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		t := extractTokenFromRequest(r)
		if t != nil {
			until := time.Unix(t.IssuedAt+g.cfg.MaxTokenSecs, 0)
			if err := g.db.BlacklistSession(t.sessionID(), until); err != nil {
				LogoutErrorHandler(w, r, NewErrorInternal(
					"",
					err,
				))
				return
			}
		}
		LogoutSuccessHandler(w, r)
	}
	return http.HandlerFunc(f)
}

// LogoutSuccessHandler returns status 200 with text "session terminated". It is
// exposed so that users can replace it with custom logic if desired.
var LogoutSuccessHandler = func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("session terminated"))
}

// LogoutErrorHandler is called if the logout fails for any reason. It is
// exposed so that users can replace it with custom logic if desired.
var LogoutErrorHandler = func(w http.ResponseWriter, r *http.Request, err *Error) {
	http.Error(w, err.Msg, http.StatusInternalServerError)
}

// ExtractUser returns the Authable from the token that is carried in the
// context of the request.
//
//	Ex.
//
//	user, ok := tinyauth.ExtractUser(r).(*User)
//	if !ok {
//	    log.Warn("failed to find *User in request context")
//	}
func ExtractUser(r *http.Request) Authable {
	t := extractTokenFromRequest(r)
	if t != nil {
		return t.user
	}
	return nil
}

// RequestWithUpdatedAuthable takes an updated Authable, regenerates the auth
// token, injects it into the response header, and returns a new request with
// the updated Authable value in context. Clients can use this to persist
// property changes for the current user into the auth token.
func (g *Guard) RequestWithUpdatedAuthable(w http.ResponseWriter, r *http.Request, a Authable) (*http.Request, error) {
	t := extractTokenFromRequest(r)
	if t == nil {
		return nil, errors.New("no tinyauth token found in the request context")
	}
	t.user = a
	return g.requestWithToken(w, r, t)
}

const authHeaderKey = "Authorization"

type contextKey struct {
	name string
}

// String returns a the string value of the context key.
func (k *contextKey) String() string {
	return "simple auth context value " + k.name
}

var tokenContextKey = &contextKey{"tinyauth Token"}

func extractTokenFromRequest(r *http.Request) *token {
	tVal := r.Context().Value(tokenContextKey)
	t, ok := tVal.(*token)
	if !ok {
		return nil
	}
	return t
}

func (g *Guard) requestWithToken(w http.ResponseWriter, r *http.Request, t *token) (*http.Request, error) {
	r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, t))
	if err := g.writeAuthHeader(w, t); err != nil {
		return nil, fmt.Errorf("failed to write token into response header: %w", err)
	}
	return r, nil
}

func (g *Guard) writeAuthHeader(w http.ResponseWriter, t *token) error {
	jwe, err := g.encodeToken(t)
	if err != nil {
		return err
	}
	w.Header().Set(authHeaderKey, bearerString(jwe))
	return nil
}

func bearerString(tokenBytes []byte) string {
	return "Bearer " + string(tokenBytes)
}
