//revive:disable:package-comments
package token

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	identitypb "buf.build/gen/go/authaas/identity/protocolbuffers/go/identity"
	realmpb "buf.build/gen/go/authaas/realm/protocolbuffers/go/realm"
)

const (
	identityID = "6f1b6f1e-4f7a-4f5e-9d9a-2b1c3d4e5f60"
	realmID    = "1c9d5a2e-7b33-4a0e-9d2f-8a7b6c5d4e3f"
	issuer     = "acme"
)

var (
	audience = []string{"api", "web"}

	minted    = time.Now().Truncate(time.Second)
	issuedAt  = minted.Unix()
	notBefore = minted.Add(-time.Minute).Unix()
	expiresAt = minted.Add(time.Hour).Unix()
)

func full(t *testing.T) *Claims {
	t.Helper()

	nbf := notBefore
	exp := expiresAt

	return &Claims{
		IdentityId: &identitypb.ID{Value: identityID},
		RealmId:    &realmpb.ID{Value: realmID},
		Iss:        issuer,
		Aud:        audience,
		Iat:        issuedAt,
		Nbf:        &nbf,
		Exp:        &exp,
	}
}

func TestMarshalJSON(t *testing.T) {
	t.Run("writes the claim names the token carries", func(t *testing.T) {
		encoded, err := json.Marshal(full(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(
			`{"sub":%q,"rid":%q,"iss":%q,"aud":["api","web"],"iat":%d,"nbf":%d,"exp":%d}`,
			identityID, realmID, issuer, issuedAt, notBefore, expiresAt,
		)

		if string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})

	t.Run("omits an audience, a not-before and an expiry that are unset", func(t *testing.T) {
		claims := full(t)
		claims.Aud = nil
		claims.Nbf = nil
		claims.Exp = nil

		encoded, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(
			`{"sub":%q,"rid":%q,"iss":%q,"iat":%d}`,
			identityID, realmID, issuer, issuedAt,
		)

		if string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})

	t.Run("writes empty subject and realm when neither is set", func(t *testing.T) {
		encoded, err := json.Marshal(&Claims{Iat: issuedAt})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(`{"sub":"","rid":"","iss":"","iat":%d}`, issuedAt)

		if string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})
}

func TestUnmarshalJSON(t *testing.T) {
	t.Run("reads back what it wrote", func(t *testing.T) {
		encoded, err := json.Marshal(full(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var decoded Claims
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := decoded.IdentityId.GetValue(); got != identityID {
			t.Errorf("identity = %q, want %q", got, identityID)
		}

		if got := decoded.RealmId.GetValue(); got != realmID {
			t.Errorf("realm = %q, want %q", got, realmID)
		}

		if decoded.Iss != issuer || decoded.Iat != issuedAt {
			t.Errorf("issuer and issued at = %q, %d", decoded.Iss, decoded.Iat)
		}

		if !slices.Equal(decoded.Aud, audience) {
			t.Errorf("audience = %v, want %v", decoded.Aud, audience)
		}

		if decoded.Nbf == nil || *decoded.Nbf != notBefore {
			t.Errorf("not before = %v, want %d", decoded.Nbf, notBefore)
		}

		if decoded.Exp == nil || *decoded.Exp != expiresAt {
			t.Errorf("expiry = %v, want %d", decoded.Exp, expiresAt)
		}
	})

	t.Run("reads an audience written as one string", func(t *testing.T) {
		var decoded Claims
		if err := json.Unmarshal([]byte(`{"aud":"api"}`), &decoded); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !slices.Equal(decoded.Aud, []string{"api"}) {
			t.Errorf("audience = %v, want [api]", decoded.Aud)
		}
	})

	t.Run("leaves a not-before and an expiry unset when the token has none", func(t *testing.T) {
		var decoded Claims
		if err := json.Unmarshal([]byte(`{}`), &decoded); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if decoded.Nbf != nil || decoded.Exp != nil {
			t.Errorf("not before = %v, expiry = %v, want both unset", decoded.Nbf, decoded.Exp)
		}
	})

	t.Run("reports a claim set that does not decode", func(t *testing.T) {
		var decoded Claims

		if err := json.Unmarshal([]byte(`{"iat":"soon"}`), &decoded); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestRegisteredClaimAccessors(t *testing.T) {
	claims := full(t)

	t.Run("answers with the issuer, audience and subject", func(t *testing.T) {
		got, err := claims.GetIssuer()
		if err != nil || got != issuer {
			t.Errorf("issuer = %q, %v", got, err)
		}

		aud, err := claims.GetAudience()
		if err != nil || !slices.Equal(aud, audience) {
			t.Errorf("audience = %v, %v", aud, err)
		}

		subject, err := claims.GetSubject()
		if err != nil || subject != identityID {
			t.Errorf("subject = %q, %v", subject, err)
		}
	})

	t.Run("answers with the times the token carries", func(t *testing.T) {
		expiry, err := claims.GetExpirationTime()
		if err != nil || expiry == nil || expiry.Unix() != expiresAt {
			t.Errorf("expiry = %v, %v", expiry, err)
		}

		issued, err := claims.GetIssuedAt()
		if err != nil || issued == nil || issued.Unix() != issuedAt {
			t.Errorf("issued at = %v, %v", issued, err)
		}

		nbf, err := claims.GetNotBefore()
		if err != nil || nbf == nil || nbf.Unix() != notBefore {
			t.Errorf("not before = %v, %v", nbf, err)
		}
	})

	t.Run("answers with no expiry and no not-before when the token has neither", func(t *testing.T) {
		unbounded := &Claims{Iat: issuedAt}

		expiry, err := unbounded.GetExpirationTime()
		if err != nil || expiry != nil {
			t.Errorf("expiry = %v, %v, want none", expiry, err)
		}

		nbf, err := unbounded.GetNotBefore()
		if err != nil || nbf != nil {
			t.Errorf("not before = %v, %v, want none", nbf, err)
		}
	})
}
