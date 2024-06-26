package applesign

import (
	"context"
	"github.com/pkg6/go-requests"
	"net/url"
)

// RevokeRefreshTokenRequest is based off https://developer.apple.com/documentation/sign_in_with_apple/revoke_tokens
type RevokeRefreshTokenRequest struct {
	// ClientID is the "Services ID" value that you get when navigating to your "sign in with Apple"-enabled service ID
	ClientID string

	// ClientSecret is secret generated as a JSON Web Token that uses the secret key generated by the WWDR portal.
	// It can also be generated using the GenerateClientSecret function provided in this package
	ClientSecret string

	// RefreshToken is the refresh token given during a previous validation
	RefreshToken string
}

func RevokeRefreshToken(ctx context.Context, req RevokeRefreshTokenRequest) error {
	data := url.Values{}
	data.Set("client_id", req.ClientID)
	data.Set("client_secret", req.ClientSecret)
	data.Set("token", req.RefreshToken)
	data.Set("token_type_hint", "refresh_token")
	resp, err := requests.New().AsForm().Post(ctx, RevokeURL, data)
	if err != nil || resp.IsError() {
		return err
	}
	return nil
}
