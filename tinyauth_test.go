package tinyauth

import (
	"errors"
	"testing"
	"time"

	"github.com/bitdabbler/tinycrypto"
)

func Test_RoundTripPassword(t *testing.T) {
	p0 := []byte("another secret")
	h0, err := HashPassword(p0)
	if err != nil {
		t.Errorf("failed to hash password: %s", err.Error())
	}
	if err := CheckPassword(h0, p0); err != nil {
		t.Errorf("round tripped password failed: %s", err.Error())
	}
}

// test values used throughout package tests ...

type tUser struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Valid   bool   `json:"valid"`
	pwdHash []byte
}

func (t *tUser) GetID() string {
	return t.ID
}

type mockDB struct {
	users     map[string]tUser
	blacklist map[string]int64
}

var (
	nsk, _     = tinycrypto.NewRandomKey()
	testKeyset = tinycrypto.NewKeysetWithKey(nsk)
	tUserProto = new(tUser)
)

var (
	aliceID  = "alice@fr.com"
	alicePwd = []byte("aPwd")
	bobID    = "bob@fr.com"
	bobPwd   = []byte("bPwd")
	eveID    = "eve@fr.com"
	evePwd   = []byte("ePwd")
)

func newMockDB() *mockDB {
	alicePwdHash, _ := HashPassword(alicePwd)
	bobPwdHash, _ := HashPassword(bobPwd)
	evePwdHash, _ := HashPassword(evePwd)

	return &mockDB{
		users: map[string]tUser{
			aliceID: {
				Name:    "Alice",
				ID:      aliceID,
				pwdHash: alicePwdHash,
				Valid:   true,
			},
			bobID: {
				Name:    "Bob",
				ID:      bobID,
				pwdHash: bobPwdHash,
				Valid:   true,
			},
			eveID: {
				Name:    "Eve",
				ID:      eveID,
				pwdHash: evePwdHash,
				Valid:   false,
			},
		},
		blacklist: map[string]int64{},
	}
}

func (db *mockDB) GetAuthable(id string, includePasswordHash bool) (user Authable, hash []byte, err error) {
	u, ok := db.users[id]
	if !ok {
		return nil, nil, errors.New("invalid user")
	}
	if !u.Valid {
		return nil, nil, errors.New("invalid user")
	}
	var h []byte
	if includePasswordHash {
		h = u.pwdHash
	}
	u.pwdHash = nil
	return &u, h, nil
}

func (db *mockDB) BlacklistSession(sessionID string, until time.Time) error {
	db.blacklist[sessionID] = until.Unix()
	return nil
}

func (db *mockDB) CheckSessionBlacklist(sessionID string) error {
	_, shunned := db.blacklist[sessionID]
	if shunned {
		return errors.New("blacklisted session")
	}
	return nil
}
