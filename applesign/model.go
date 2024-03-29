package applesign

var (
	// ValidationURL is the endpoint for verifying tokens
	ValidationURL = "https://appleid.apple.com/auth/token"
	// RevokeURL is the endpoint for revoking tokens
	RevokeURL = "https://appleid.apple.com/auth/revoke"
)

// ValidationTokenResponse
//https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type ValidationTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}
