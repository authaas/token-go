//revive:disable:package-comments
package token

import (
	"encoding/json"
	"time"

	identitypb "buf.build/gen/go/authaas/identity/protocolbuffers/go/identity"
	realmpb "buf.build/gen/go/authaas/realm/protocolbuffers/go/realm"
	tokenpb "buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the token SDK's JWT as jwt.Claims
type Claims tokenpb.JWT

// claims is the encoded form of Claims: the registered and private claim
// names, each holding the scalar JWT defines for it.
type claims struct {
	Sub string           `json:"sub"`
	Rid string           `json:"rid"`
	Iss string           `json:"iss"`
	Aud jwt.ClaimStrings `json:"aud,omitempty"`
	Iat int64            `json:"iat"`
	Nbf *int64           `json:"nbf,omitempty"`
	Exp *int64           `json:"exp,omitempty"`
}

// MarshalJSON implements json.Marshaler
func (t *Claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(claims{
		Sub: t.IdentityId.GetValue(),
		Rid: t.RealmId.GetValue(),
		Iss: t.Iss,
		Aud: t.Aud,
		Iat: t.Iat,
		Nbf: t.Nbf,
		Exp: t.Exp,
	})
}

// UnmarshalJSON implements json.Unmarshaler
func (t *Claims) UnmarshalJSON(data []byte) error {
	var c claims
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	t.IdentityId = &identitypb.ID{Value: c.Sub}
	t.RealmId = &realmpb.ID{Value: c.Rid}
	t.Iss = c.Iss
	t.Aud = c.Aud
	t.Iat = c.Iat
	t.Nbf = c.Nbf
	t.Exp = c.Exp

	return nil
}

// GetIssuer implements jwt.Claims.GetIssuer
func (t *Claims) GetIssuer() (string, error) {
	return t.Iss, nil
}

// GetAudience implements jwt.Claims.GetAudience
func (t *Claims) GetAudience() (jwt.ClaimStrings, error) {
	return t.Aud, nil
}

// GetSubject implements jwt.Claims.GetSubject
func (t *Claims) GetSubject() (string, error) {
	return t.IdentityId.GetValue(), nil
}

// GetExpirationTime implements jwt.Claims.GetExpirationTime
// Returns nil if Exp is nil (never expires)
func (t *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if t.Exp == nil {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(*t.Exp, 0)), nil
}

// GetIssuedAt implements jwt.Claims.GetIssuedAt
func (t *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(t.Iat, 0)), nil
}

// GetNotBefore implements jwt.Claims.GetNotBefore
// Returns nil if Nbf is nil (not set)
func (t *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if t.Nbf == nil {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(*t.Nbf, 0)), nil
}
