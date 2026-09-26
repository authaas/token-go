//revive:disable:package-comments
package token

import (
	"encoding/json"
	"time"

	identitypb "buf.build/gen/go/authaas/identity/protocolbuffers/go/identity"
	realmpb "buf.build/gen/go/authaas/realm/protocolbuffers/go/realm"
	tokenpb "buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// Claims is the token SDK's JWT as jwt.Claims
type Claims tokenpb.JWT

// claims is the encoded form of Claims' typed fields: the registered and
// private claim names, each holding the scalar JWT defines for it.
type claims struct {
	Rid string           `json:"rid"`
	Iid string           `json:"iid"`
	Iss string           `json:"iss"`
	Aud jwt.ClaimStrings `json:"aud"`
	Iat int64            `json:"iat"`
	Nbf *int64           `json:"nbf"`
	Exp *int64           `json:"exp"`
}

// MarshalJSON implements json.Marshaler
func (t *Claims) MarshalJSON() ([]byte, error) {
	set := t.Additional.AsMap()

	set["rid"] = t.RealmId.GetValue()
	set["iid"] = t.IdentityId.GetValue()
	set["iss"] = t.Iss
	set["iat"] = t.Iat

	delete(set, "aud")
	if len(t.Aud) > 0 {
		set["aud"] = t.Aud
	}

	delete(set, "nbf")
	if t.Nbf != nil {
		set["nbf"] = *t.Nbf
	}

	delete(set, "exp")
	if t.Exp != nil {
		set["exp"] = *t.Exp
	}

	return json.Marshal(set)
}

// UnmarshalJSON implements json.Unmarshaler
func (t *Claims) UnmarshalJSON(data []byte) error {
	additional := &structpb.Struct{}
	if err := protojson.Unmarshal(data, additional); err != nil {
		return err
	}

	var c claims
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	t.RealmId = &realmpb.ID{Value: c.Rid}
	delete(additional.Fields, "rid")

	t.IdentityId = &identitypb.ID{Value: c.Iid}
	delete(additional.Fields, "iid")

	t.Iss = c.Iss
	delete(additional.Fields, "iss")

	t.Aud = c.Aud
	delete(additional.Fields, "aud")

	t.Iat = c.Iat
	delete(additional.Fields, "iat")

	t.Nbf = c.Nbf
	delete(additional.Fields, "nbf")

	t.Exp = c.Exp
	delete(additional.Fields, "exp")

	t.Additional = additional
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
	return t.Additional.GetFields()["sub"].GetStringValue(), nil
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
