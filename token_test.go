package tinyauth

import (
	"reflect"
	"testing"
	"time"
)

func Test_extractBearerToken(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"empty fails",
			args{""},
			"",
			true,
		},
		{
			"missing prefix fails",
			args{"the_jwe"},
			"",
			true,
		},
		{
			"succeeds with bearer prefix",
			args{"Bearer the_jwe"},
			"the_jwe",
			false,
		},
		{
			"succeeds with bearer prefix, case insensitive",
			args{"bearer the_jwe"},
			"the_jwe",
			false,
		},
		{
			"fails if prefix not follewed by space",
			args{"bearerthe_jwe"},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			got, err := extractBearerToken(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"extractBearerToken() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)
				return
			}
			if got != tt.want {
				t.Errorf(
					"extractBearerToken() = %v, want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestJWERountTrip(t *testing.T) {
	db := newMockDB()

	g := &Guard{
		cfg:           defaultTokenConfig,
		userPrototype: tUserProto,
		db:            db,
		keyset:        testKeyset,
	}

	u, _, _ := db.GetAuthable(aliceID, false)

	tok := newToken(u)

	jwe, err := g.encodeToken(tok)
	if err != nil {
		t.Errorf(
			"token -> JWE failed: %s",
			err.Error(),
		)
		t.FailNow()
	}
	tok2, err := g.decodeToken(jwe)
	if err != nil {
		t.Errorf(
			"token -> JWE failed: %s",
			err.Error(),
		)
		t.FailNow()
	}

	if !reflect.DeepEqual(tok, tok2) {
		t.Errorf(
			"\ntoken0: %+v\ntoken1: %+v\nuser0: %+v\nuser1: %+v",
			tok,
			tok2,
			tok.user,
			tok2.user,
		)
		t.FailNow()
	}
}

func Test_guard_check(t *testing.T) {

	db := newMockDB()

	now := time.Now().Unix()

	goodU, _, _ := db.GetAuthable(aliceID, false)
	badU, _, _ := db.GetAuthable(bobID, false)

	badUserToken := &token{
		IssuedAt:   now - 15,
		VerifiedAt: now - 15,
		TouchedAt:  now - 15,
		user:       badU,
	}

	db.blacklist[badUserToken.sessionID()] = time.Now().Add(100).Unix()

	g := &Guard{
		cfg: TokenConfig{
			MaxTrustSecs: 10,
			MaxStaleSecs: 20,
			MaxTokenSecs: 40,
		},
		userPrototype: tUserProto,
		db:            db,
		keyset:        testKeyset,
	}

	tests := []struct {
		name    string
		tok     *token
		wantErr bool
	}{
		{
			name: "succeed if still in trust window",
			tok: &token{
				IssuedAt:   now - 1,
				VerifiedAt: now - 1,
				TouchedAt:  now - 1,
				user:       goodU,
			},
			wantErr: false,
		},
		{
			name: "fail if older than max token life",
			tok: &token{
				IssuedAt:   now - 50,
				VerifiedAt: now,
				TouchedAt:  now,
				user:       goodU,
			},
			wantErr: true,
		},
		{
			name: "fail if token not too old, but is inactive too long",
			tok: &token{
				IssuedAt:   now - 30,
				VerifiedAt: now - 30,
				TouchedAt:  now - 30,
				user:       goodU,
			},
			wantErr: true,
		},
		{
			name: "succeed if transparent refresh returns no error",
			tok: &token{
				IssuedAt:   now - 15,
				VerifiedAt: now - 15,
				TouchedAt:  now - 15,
				user:       goodU,
			},
			wantErr: false,
		},
		{
			name:    "fail if transparent refresh returns an error",
			tok:     badUserToken,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := g.check(tt.tok); (err != nil) != tt.wantErr {
				t.Errorf(
					"guard.check() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}
