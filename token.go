package tinyauth

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/bitdabbler/tinycrypto"
)

// Time constants for convenience.
const (
	Second = int64(1)
	Minute = Second * 60
	Hour   = Minute * 60
)

// TokenConfig defines the behavior of the auth token.
type TokenConfig struct {

	// Longest period between db checks.
	MaxTrustSecs int64

	// Longest inactive period between logins.
	MaxStaleSecs int64

	// Longest period between logins.
	MaxTokenSecs int64
}

var defaultTokenConfig = TokenConfig{
	MaxTokenSecs: Hour * 14,
	MaxStaleSecs: Hour,
	MaxTrustSecs: Minute * 10,
}

// token holds token session details.
type token struct {
	user       Authable
	UserBytes  json.RawMessage `json:"user_bytes"`
	IssuedAt   int64           `json:"issued_at"`
	VerifiedAt int64           `json:"verified_at"`
	TouchedAt  int64           `json:"touched_at"`
}

func newToken(a Authable) *token {
	vat := time.Now().Unix()
	t := &token{
		IssuedAt:   vat,
		VerifiedAt: vat,
		TouchedAt:  vat,
		user:       a,
	}
	return t
}

// Guard holds the state used for authentication. Auth middleware are therefore
// defined as methods on the Guard.
type Guard struct {
	userPrototype Authable
	db            Repo
	keyset        *tinycrypto.Keyset
	cfg           TokenConfig
}

// NewGuard creates an authenticator using the default configuration.
func NewGuard(keyset *tinycrypto.Keyset, db Repo, userPrototypePtr Authable) *Guard {
	return CustomGuard(defaultTokenConfig, keyset, db, userPrototypePtr)
}

// CustomGuard creates an authenticator with a custom configuration.
func CustomGuard(cfg TokenConfig, keyset *tinycrypto.Keyset, db Repo, userPrototypePtr Authable) *Guard {
	v := reflect.ValueOf(userPrototypePtr)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		log.Fatalf("the prototype user must be a non-nil pointer")
	}
	return &Guard{
		cfg:           cfg,
		userPrototype: userPrototypePtr,
		db:            db,
		keyset:        keyset,
	}
}

func (t *token) sessionID() string {
	h := md5.New()
	fmt.Fprintf(h, "%s-%d", t.user.GetID(), t.IssuedAt)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func extractBearerToken(s string) (string, error) {
	if len(s) > 7 && strings.ToUpper(s[0:7]) == "BEARER " {
		return s[7:], nil
	}
	return "", errors.New("'Bearer' token not found")
}

func (g *Guard) decodeToken(raw []byte) (*token, error) {
	tBytes, err := g.keyset.Decrypt(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}
	var t token
	if err := json.Unmarshal(tBytes, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	u := reflect.ValueOf(g.userPrototype).Interface()
	if err := json.Unmarshal(t.UserBytes, u); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Authable from token: %w", err)
	}
	a, ok := u.(Authable)
	if !ok {
		return nil, errors.New("failed to cast the Authable value in token")
	}
	t.user = a
	return &t, nil
}

// encodeToken returns a JWE of the auth token.
func (g *Guard) encodeToken(t *token) ([]byte, error) {
	ub, err := json.Marshal(t.user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal passport holder to JSON: %w", err)
	}
	t.UserBytes = ub
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session token to JSON% w", err)
	}
	return g.keyset.Encrypt(raw)
}

func (g *Guard) check(t *token) error {
	now := time.Now().Unix()
	age := now - t.IssuedAt
	staleness := now - t.TouchedAt
	trusted := now - t.VerifiedAt
	if age > g.cfg.MaxTokenSecs {
		log.Printf(
			"auth token age: %d, limit: %d",
			age,
			g.cfg.MaxTokenSecs,
		)
		return errors.New("auth token expired")
	}
	if staleness > g.cfg.MaxStaleSecs {
		log.Printf(
			"auth token staleness: %d, limit: %d",
			staleness,
			g.cfg.MaxStaleSecs,
		)
		return errors.New("auth token expired from inactivity")
	}
	if trusted > g.cfg.MaxTrustSecs {
		log.Printf(
			"token trusted: %d, limit: %d; transparently refreshing",
			trusted,
			g.cfg.MaxTrustSecs,
		)
		if err := g.db.CheckSessionBlacklist(t.sessionID()); err != nil {
			return fmt.Errorf("unable to extend session: %w", err)
		}
		t.VerifiedAt = now
	}
	t.TouchedAt = now
	return nil
}
