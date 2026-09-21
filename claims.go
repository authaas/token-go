//revive:disable:package-comments
package token

import (
	"time"

	tokenpb "buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the token SDK's JWT as jwt.Claims
type Claims tokenpb.JWT

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
	return t.Sub, nil
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
