package applesign

import (
	jwt2 "github.com/golang-jwt/jwt"
	"github.com/pkg6/applego/jwt"
	"github.com/pkg6/applego/utility"
	"time"
)

//GenerateClientSecret
//生成用于向验证服务器发出请求的客户端机密。
//该秘密将在180天后过期
//signingKey-通过进入开发者部分的密钥部分获得的来自苹果的私钥
//teamID-您的10个字符的团队ID
//clientID-您的服务ID，例如com.test.Services
func GenerateClientSecret(signingKey, teamID, clientID, keyID string) (string, error) {
	privKey, err := utility.EcdsaPrivateKey([]byte(signingKey))
	if err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Encode(privKey, jwt2.SigningMethodES256, &jwt2.StandardClaims{
		Issuer:   teamID,
		IssuedAt: now.Unix(),
		// 180 days
		ExpiresAt: now.Add(time.Hour*24*180 - time.Second).Unix(),
		Audience:  "https://appleid.apple.com",
		Subject:   clientID,
	}, map[string]interface{}{
		"alg": "ES256",
		"kid": keyID,
	})
}

func IDTokenClaims(idToken string) (jwt.MapClaims, error) {
	decode, err := jwt.Decode(idToken)
	if err != nil {
		return jwt.MapClaims{}, nil
	}
	return decode.Claims, nil
}
