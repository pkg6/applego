package applesign

import (
	"github.com/pkg6/applego/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

//openssl ecparam -name prime256v1 -genkey -noout -out private.pem
//openssl ec -in private.pem -pubout -out public.pem
//openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem
func TestGenerateClientSecret(t *testing.T) {
	testGoodKey := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNxUSKRcJInSebfRD
eWXM/rakImnzV8H8WCkEzUDdcTuhRANCAAQQjgRYI8H05fKzXdIoj8mHicpGZFhE
6pDILEYQlt7ZhS0pcGCmpZLJDyn+s01Os5vDWb2zSTSX+0UgRphCuMfw
-----END PRIVATE KEY-----` // A revoked key that can be used for testing
	tests := []struct {
		name       string
		signingKey string
		wantSecret bool
		wantErr    bool
	}{
		{
			name:       "bad key",
			signingKey: "bad_key",
			wantSecret: false,
			wantErr:    true,
		},
		{
			name:       "good key",
			signingKey: testGoodKey,
			wantSecret: true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateClientSecret(tt.signingKey, "1234567890", "com.example.app", "0987654321")
			if !tt.wantErr {
				assert.NoError(t, err, "expected no error but got %s", err)
			}
			if tt.wantSecret {
				assert.NotEmpty(t, got, "wanted a secret string returned but got none")
				decoded, err := jwt.Decode(got)
				assert.NoError(t, err, "error while decoding the secret")
				r := decoded.Claims.StandardClaims().Issuer
				assert.Equal(t, "1234567890", r)
				r2 := decoded.Claims.StandardClaims().Subject
				assert.Equal(t, "com.example.app", r2)
			}
		})
	}
}
func TestIDTokenClaims(t *testing.T) {
	tests := []struct {
		name      string
		idToken   string
		wantEmail string
		wantErr   bool
	}{
		{
			name:      "successful decode",
			idToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmV4YW1wbGUuYXBwIiwiZXhwIjoxNTY4Mzk1Njc4LCJpYXQiOjE1NjgzOTUwNzgsInN1YiI6IjA4MjY0OS45MzM5MWQ4ZTExOTJmNTZiOGMxY2gzOWdzMmE0N2UyLjk3MzIiLCJhdF9oYXNoIjoickU3b3Brb1BSeVBseV9Pc2Rhc2RFQ1ZnIiwiZW1haWwiOiJmb29AYmFyLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNTY4Mzk1MDc2fQ.yPyUS_5k8RMvfowGylHqiCJqYwe-AOGtpBnjvqP4Na8",
			wantEmail: "foo@bar.com",
			wantErr:   false,
		},
		{
			name:      "bad token",
			idToken:   "badtoken",
			wantEmail: "",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IDTokenClaims(tt.idToken)
			if !tt.wantErr {
				assert.NoError(t, err, "expected no error but received %s", err)
			}

			if tt.wantEmail != "" {
				assert.Equal(t, tt.wantEmail, got["email"])
			}
		})
	}
}
