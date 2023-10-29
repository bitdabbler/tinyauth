// Package tinyauth provides super simple token-based authentication tools that
// are compatible with the standard library HTTP handler APIs. It uses
// authenticated encryption by default, to ensure the authenticity, privacy, and
// integrity of the token content. tinyauth was designed to keep the API minimal
// while still being easy to integrate with existing services and user models.
package tinyauth

import (
	"time"

	"github.com/bitdabbler/acrypt"
)

// Authable represents a user.
type Authable interface {
	GetID() (id string)
}

// Repo defines the data persistence API for auth-related entities.
type Repo interface {

	// GetAuthable returns the user with the given ID, IF valid. If the password
	// hash is required, it is returned separately and will immediately be
	// discarded after the user is authenticated.
	GetAuthable(id string, includePasswordHash bool) (user Authable, hash []byte, err error)

	// BlacklistSession registers a session as dead, so that it cannot be used
	// to auto-refresh an auth token. The repo is also provided with a timestamp
	// indicating when it will become safe to prune the session.
	BlacklistSession(sessionID string, until time.Time) error

	// CheckSessionBlacklist returns nil if the sessionID is NOT present in the
	// dead session blacklist.
	CheckSessionBlacklist(sessionID string) error
}

// HashPassword re-exports the password hash utility used (currently acrypt).
func HashPassword(password []byte) (hash []byte, err error) {
	return acrypt.GenerateFromPassword(password, nil)
}

// CheckPassword re-exports the hash/password authentication utility used.
func CheckPassword(hash, password []byte) error {
	return acrypt.CompareHashAndPassword(hash, password)
}
