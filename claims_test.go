//revive:disable:package-comments
package token

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"
	"uuid"

	identitypb "buf.build/gen/go/authaas/identity/protocolbuffers/go/identity"
	realmpb "buf.build/gen/go/authaas/realm/protocolbuffers/go/realm"
	"google.golang.org/protobuf/types/known/structpb"
)

const issuer = "acme"

var (
	identityID = uuid.New().String()
	realmID    = uuid.New().String()
	subject    = uuid.New().String()

	audience = []string{"api", "web"}

	minted    = time.Now().Truncate(time.Second)
	issuedAt  = minted.Unix()
	notBefore = minted.Add(-time.Minute).Unix()
	expiresAt = minted.Add(time.Hour).Unix()
)

func additional(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()

	s, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return s
}

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
		Additional: additional(t, map[string]any{
			"sub":    subject,
			"groups": []any{"admins"},
		}),
	}
}

func TestMarshalJSON(t *testing.T) {
	t.Run("writes the typed claims beside every additional one", func(t *testing.T) {
		encoded, err := json.Marshal(full(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(
			`{"aud":["api","web"],"exp":%d,"groups":["admins"],"iat":%d,"iid":%q,"iss":%q,"nbf":%d,"rid":%q,"sub":%q}`,
			expiresAt, issuedAt, identityID, issuer, notBefore, realmID, subject,
		)

		if string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})

	t.Run("gives no additional claim a typed claim's name, set or not", func(t *testing.T) {
		claims := &Claims{
			IdentityId: &identitypb.ID{Value: identityID},
			RealmId:    &realmpb.ID{Value: realmID},
			Iss:        issuer,
			Iat:        issuedAt,
			Additional: additional(t, map[string]any{
				"rid": subject,
				"iid": subject,
				"iss": subject,
				"iat": float64(expiresAt),
				"aud": subject,
				"nbf": float64(notBefore),
				"exp": float64(expiresAt),
			}),
		}

		encoded, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(
			`{"iat":%d,"iid":%q,"iss":%q,"rid":%q}`,
			issuedAt, identityID, issuer, realmID,
		)

		if string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})

	t.Run("writes empty realm, identity and issuer when none is set", func(t *testing.T) {
		encoded, err := json.Marshal(&Claims{Iat: issuedAt})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fmt.Sprintf(`{"iat":%d,"iid":"","iss":"","rid":""}`, issuedAt)

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

		fields := decoded.Additional.GetFields()

		if len(fields) != 2 {
			t.Errorf("additional = %v, want only sub and groups", fields)
		}

		if got := fields["sub"].GetStringValue(); got != subject {
			t.Errorf("sub = %q, want %q", got, subject)
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

	t.Run("reports a claim set that is not an object", func(t *testing.T) {
		var decoded Claims

		if err := json.Unmarshal([]byte(`[]`), &decoded); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("reports a typed claim of the wrong type", func(t *testing.T) {
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

		sub, err := claims.GetSubject()
		if err != nil || sub != subject {
			t.Errorf("subject = %q, %v", sub, err)
		}
	})

	t.Run("answers with no subject when the token carries none", func(t *testing.T) {
		sub, err := (&Claims{}).GetSubject()
		if err != nil || sub != "" {
			t.Errorf("subject = %q, %v, want none", sub, err)
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
