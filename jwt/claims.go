package jwt

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt"
)

type MapClaims map[string]any

func (m MapClaims) StandardClaims() jwt.StandardClaims {
	var claims jwt.StandardClaims
	mapJson, _ := json.Marshal(m)
	_ = json.Unmarshal(mapJson, &claims)
	return claims
}

// VerifyAudience Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	var aud []string
	switch v := m["aud"].(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return false
			}
			aud = append(aud, vs)
		}
	}
	return verifyAud(aud, cmp, req)
}

// VerifyExpiresAt
// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	exp, ok := m["exp"]
	if !ok {
		return !req
	}
	switch expType := exp.(type) {
	case float64:
		return verifyExp(int64(expType), cmp, req)
	case json.Number:
		v, _ := expType.Int64()
		return verifyExp(v, cmp, req)
	}
	return false
}

// VerifyIssuedAt
//Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	iat, ok := m["iat"]
	if !ok {
		return !req
	}
	switch iatType := iat.(type) {
	case float64:
		return verifyIat(int64(iatType), cmp, req)
	case json.Number:
		v, _ := iatType.Int64()
		return verifyIat(v, cmp, req)
	}
	return false
}

// VerifyIssuer
//Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// VerifyNotBefore
//Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	nbf, ok := m["nbf"]
	if !ok {
		return !req
	}
	switch nbfType := nbf.(type) {
	case float64:
		return verifyNbf(int64(nbfType), cmp, req)
	case json.Number:
		v, _ := nbfType.Int64()
		return verifyNbf(v, cmp, req)
	}
	return false
}

// Valid
// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := jwt.TimeFunc().Unix()
	if !m.VerifyExpiresAt(now, false) {
		vErr.Inner = errors.New("token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !m.VerifyIssuedAt(now, false) {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !m.VerifyNotBefore(now, false) {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}
	return vErr
}

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	// use a var here to keep constant time compare when looping over a number of claims
	result := false
	var stringClaims string
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			result = true
		}
		stringClaims = stringClaims + a
	}
	// case where "" is sent in one or many aud claims
	if len(stringClaims) == 0 {
		return !required
	}
	return result
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}

// ValidationError
//The error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}
