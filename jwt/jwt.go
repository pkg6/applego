package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
)

type JWTDecode struct {
	Token  string
	Header Header
	Claims MapClaims
}

// Encode 加密token
func Encode(key interface{}, method jwt.SigningMethod, claims jwt.Claims, header map[string]any) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	token.Header = header
	return token.SignedString(key)
}

// Decode Parsing token content
func Decode(token string) (*JWTDecode, error) {
	var err error
	parts := strings.Split(token, ".")
	var header Header
	err = decodeAndUnmarshall(parts[0], &header)
	if err != nil {
		return nil, err
	}
	var claims MapClaims
	err = decodeAndUnmarshall(parts[1], &claims)
	if err != nil {
		return nil, err
	}
	return &JWTDecode{
		Token:  token,
		Header: header,
		Claims: claims,
	}, err
}

func decodeAndUnmarshall(part string, value any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return fmt.Errorf("cannot encode the %s", part)
	}
	err = json.Unmarshal(decoded, value)
	if err != nil {
		return fmt.Errorf("cannot encode the %s", part)
	}
	return nil
}
