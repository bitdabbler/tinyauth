package tinyauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newRequestWithBody(body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", "http://test.com", body)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func newRequestWithToken(t interface{}) *http.Request {
	r := httptest.NewRequest("", "http://test.com", nil)
	r.Header.Set("Content-Type", "application/json")
	if t == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), tokenContextKey, t))
}

func Test_GuardMiddleware(t *testing.T) {
	db := newMockDB()
	g := NewGuard(testKeyset, db, tUserProto)
	w := &httptest.ResponseRecorder{}
	r := newRequestWithToken(nil)
	var tokenOut *token

	sensitiveFunc := func(w http.ResponseWriter, r *http.Request) {
		// middleware should inject token
		tokenOut = extractTokenFromRequest(r)
		w.WriteHeader(http.StatusOK)
	}
	h := g.Middleware(http.HandlerFunc(sensitiveFunc))
	h.ServeHTTP(w, r)

	// with no auth header, the middleware should reject the call
	if w.Code != http.StatusUnauthorized {
		t.Errorf(
			"with no auth header, expected %d, but got %d",
			http.StatusUnauthorized,
			w.Code,
		)
	}

	// no a malformed auth header, the middleware should reject the call
	r.Header.Set(authHeaderKey, "")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf(
			"with no bearer token, expected %d, but got %d",
			http.StatusUnauthorized,
			w.Code,
		)
	}

	// with an invalid token, the middleware should reject the call
	r.Header.Set(authHeaderKey, "Bearer badtoken")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf(
			"with bad token, expected %d, but got %d",
			http.StatusUnauthorized,
			w.Code,
		)
	}

	// - injects good token in context and header
	now := time.Now().Unix() - 1
	tok := &token{
		IssuedAt:   now,
		VerifiedAt: now,
		TouchedAt:  now,
	}
	r, _ = g.requestWithToken(w, r, tok)

	// the w here is the outbound writer, copy its token into our inbound r
	r.Header.Set(authHeaderKey, w.Header().Get(authHeaderKey))

	// reset w after abusing it to catch our encoded token above
	w = &httptest.ResponseRecorder{}

	// now test the happy path
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf(
			"with good token expected %d, but got %d",
			http.StatusOK,
			w.Code,
		)
	}
	if diff := tokenOut.TouchedAt - tok.TouchedAt; diff < 1 {
		t.Errorf(
			"the token timestamp should be bumped with each request",
		)
	}
}

func Test_LoginStatus(t *testing.T) {

	db := newMockDB()
	login := NewGuard(testKeyset, db, tUserProto).LoginHandler()

	tests := []struct {
		name     string
		payload  string
		expected int
	}{
		{
			name:     "empty login form",
			payload:  "{}",
			expected: http.StatusBadRequest,
		},
		{
			name: "login form missing password",
			payload: fmt.Sprintf(
				`{"user_id":"%s"}`,
				aliceID,
			),
			expected: http.StatusBadRequest,
		},
		{
			name: "login form missing user_id",
			payload: fmt.Sprintf(
				`{"password":"%s"}`,
				string(alicePwd),
			),
			expected: http.StatusBadRequest,
		},
		{
			name: "valid user's credentials",
			payload: fmt.Sprintf(
				`{"user_id":"%s","password":"%s"}`,
				aliceID,
				string(alicePwd),
			),
			expected: http.StatusOK,
		},
		{
			name: "valid user bad password",
			payload: fmt.Sprintf(
				`{"user_id":"%s","password":"%s"}`,
				aliceID,
				"notalicespassword",
			),
			expected: http.StatusUnauthorized,
		},
		{
			name:     "random credentials",
			payload:  `{"user_id":"randy","password":"random"}`,
			expected: http.StatusUnauthorized,
		},
		{
			name: "good credentials for an invalid user",
			payload: fmt.Sprintf(
				`{"user_id":"%s","password":"%s"}`,
				eveID,
				evePwd,
			),
			expected: http.StatusUnauthorized,
		},
	}

	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		// for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRequestWithBody(bytes.NewBufferString(tt.payload))
			w := &httptest.ResponseRecorder{}
			login.ServeHTTP(w, r)
			if w.Code != tt.expected {
				t.Errorf(
					"with credentials, expected %d, but got %d",
					tt.expected,
					w.Code,
				)
			}
		})
	}
}

func Test_LoginAuthHeader(t *testing.T) {

	db := newMockDB()
	g := NewGuard(testKeyset, db, tUserProto)
	login := g.LoginHandler()

	payload := fmt.Sprintf(
		`{"user_id":"%s","password":"%s"}`,
		aliceID,
		string(alicePwd),
	)
	r := newRequestWithBody(bytes.NewBufferString(payload))
	w := &httptest.ResponseRecorder{}
	login.ServeHTTP(w, r)

	// we logged in successfully, so we should have an auth header
	authHeader := w.Header().Get(authHeaderKey)

	// and that should work to send another request to the server, to access a
	// protected endpoint
	r = newRequestWithBody(nil)
	r.Header.Set(authHeaderKey, authHeader)
	w = &httptest.ResponseRecorder{}
	sensitiveEndpoint := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	protected := g.Middleware(http.HandlerFunc(sensitiveEndpoint))
	protected.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf(
			"using auth header from login, expected %d, but got %d",
			http.StatusOK,
			w.Code,
		)
	}
}

func Test_ExtractUser(t *testing.T) {

	u := &tUser{Name: "Alice"}
	tok := &token{IssuedAt: 17, VerifiedAt: 27, TouchedAt: 37}
	tok2 := &token{IssuedAt: 17, VerifiedAt: 27, TouchedAt: 37, user: u}
	tests := []struct {
		name string
		req  *http.Request
		want Authable
	}{
		{
			name: "should fail if no token value in context",
			req:  newRequestWithToken(nil),
			want: (Authable)(nil),
		},
		{
			name: "should fail if value in context is not a *token",
			req:  newRequestWithToken(&tUser{}),
			want: (Authable)(nil),
		},
		{
			name: "should fail if token has no user",
			req:  newRequestWithToken(tok),
			want: (Authable)(nil),
		},
		{
			name: "should return a *user if in the *token in context",
			req:  newRequestWithToken(tok2),
			want: u,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractUser(tt.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractTokenFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Logout(t *testing.T) {
	db := newMockDB()
	cfg := TokenConfig{
		MaxTrustSecs: 20,
		MaxStaleSecs: 60,
		MaxTokenSecs: 120,
	}
	g := CustomGuard(cfg, testKeyset, db, tUserProto)

	logout := g.LogoutHandler()

	good, _, _ := db.GetAuthable(aliceID, false)
	tok := newToken(good)

	// skip mw and add to context directly
	r := newRequestWithToken(tok)
	w := new(httptest.ResponseRecorder)
	expected := http.StatusOK

	logout.ServeHTTP(w, r)
	if w.Code != expected {
		t.Errorf(
			"logout accepted if session blacklisted, expected %d, but got %d",
			expected,
			w.Code,
		)
	}
	until, ok := db.blacklist[tok.sessionID()]
	if !ok {
		t.Errorf("expected sessionID not in blacklist: %v", db.blacklist)
		t.FailNow()
	}
	expected = int(tok.IssuedAt + cfg.MaxTokenSecs)
	if int(until) != expected {
		t.Errorf("purge time delta; expected %d, but got %d", expected, until)
		t.FailNow()
	}

	r = newRequestWithToken(nil)
	w = new(httptest.ResponseRecorder)
	expected = http.StatusOK
	logout.ServeHTTP(w, r)
	if w.Code != expected {
		t.Errorf(
			"without auth header, reveal nothing; expected %d, but got %d",
			expected,
			w.Code,
		)
	}
}

func Test_RequestWithUpdatedAuthable(t *testing.T) {
	// if there is no token in context, it should fail
	// if there is a user in the token in context, both the context and the
	// header should be overwritten

	db := newMockDB()
	g := NewGuard(testKeyset, db, tUserProto)

	u, _, _ := db.GetAuthable(aliceID, false)

	r := newRequestWithToken(nil)
	w := new(httptest.ResponseRecorder)
	_, err := g.RequestWithUpdatedAuthable(w, r, u)
	if err == nil {
		t.Errorf("should fail if no token is in the request context")
		t.FailNow()
	}

	tok := newToken(u)
	r = newRequestWithToken(tok)
	r, err = g.RequestWithUpdatedAuthable(w, r, u)
	if err != nil {
		t.Errorf("RequestWithUpdatedAuthable failed: %v", err)
		t.FailNow()
	}
	t2, ok := r.Context().Value(tokenContextKey).(*token)
	if t2 == nil || !ok {
		t.Errorf("token missing from request")
		t.FailNow()
	}
	u2, ok := t2.user.(*tUser)
	if u2 == nil || !ok {
		t.Errorf("user missing from request token")
		t.FailNow()
	}
	if !reflect.DeepEqual(u, u2) {
		t.Errorf("updated user did not match the one in the token")
	}
	h := w.Header().Get(authHeaderKey)
	if !strings.HasPrefix(h, "Bearer ") {
		t.Error("RequestWithUpdatedAuthable should inject updated token into auth header")
	}
}
