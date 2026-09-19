//revive:disable:package-comments
package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GetIssuer implements jwt.Claims.GetIssuer
func (t *JWT) GetIssuer() (string, error) {
	return t.Iss, nil
}

// GetAudience implements jwt.Claims.GetAudience
func (t *JWT) GetAudience() (jwt.ClaimStrings, error) {
	return t.Aud, nil
}

// GetSubject implements jwt.Claims.GetSubject
func (t *JWT) GetSubject() (string, error) {
	return t.Sub, nil
}

// GetExpirationTime implements jwt.Claims.GetExpirationTime
// Returns nil if Exp is nil (never expires)
func (t *JWT) GetExpirationTime() (*jwt.NumericDate, error) {
	if t.Exp == nil {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(t.GetExp(), 0)), nil
}

// GetIssuedAt implements jwt.Claims.GetIssuedAt
func (t *JWT) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(t.Iat, 0)), nil
}

// GetNotBefore implements jwt.Claims.GetNotBefore
// Returns nil if Nbf is nil (not set)
func (t *JWT) GetNotBefore() (*jwt.NumericDate, error) {
	if t.Nbf == nil {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(t.GetNbf(), 0)), nil
}
