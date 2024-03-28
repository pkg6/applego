package applepay

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/pkg6/applego/utility"
	"github.com/pkg6/go-requests"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	apiUrl    = "https://api.storekit.itunes.apple.com"
	apiBoxUrl = "https://api.storekit-sandbox.itunes.apple.com"

	// Get Transaction History
	getTransactionHistory = "/inApps/v1/history/%s" // transactionId
	// Get Transaction Info
	getTransactionInfo = "/inApps/v1/transactions/%s" // transactionId
	// Get All Subscription Statuses
	getAllSubscriptionStatuses = "/inApps/v1/subscriptions/%s" // transactionId
	// Send Consumption Information
	sendConsumptionInformation = "/inApps/v1/transactions/consumption/%s" // transactionId
	// Look Up Order ID
	lookUpOrderID = "/inApps/v1/lookup/%s" // orderId
	// Get Subscription Status
	getRefundHistory = "/inApps/v2/refund/lookup/%s" // transactionId
	// Get Notification History
	getNotificationHistory = "/inApps/v1/notifications/history"
)

type ResponseErrorMessage struct {
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}
type SignedTransaction string

func (s *SignedTransaction) DecodeSignedTransaction() (ti *TransactionsItem, err error) {
	if *s == "" {
		return nil, errors.New("signedTransactions is empty")
	}
	ti = new(TransactionsItem)
	if err = ExtractClaims(string(*s), ti); err != nil {
		return nil, err
	}
	return ti, nil
}

type ApiClientConfig struct {
	ISS          string `json:"iss"`
	BID          string `json:"bid"`
	KeyID        string `json:"keyID"`
	PrivateKey   string `json:"privateKey"`
	IsProduction bool   `json:"isProduction"`
}

func (config *ApiClientConfig) NewApi() (api *ApiClient, err error) {
	var privateKey []byte
	if utility.IsFile(config.PrivateKey) {
		privateKey, err = os.ReadFile(config.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey = []byte(config.PrivateKey)
	}
	return NewApiClient(config.ISS, config.BID, config.KeyID, privateKey, config.IsProduction)
}

type ApiClient struct {
	//https://appstoreconnect.apple.com/access/api/subs
	// Your issuer ID from the Key page in App Store Connect (exp: "57246542-96fe-1a63-e053-0824d011072a")
	Iss string
	//Your app’s bundle ID (exp: "com.example.testbundleid2021")
	Bid string
	//Your private key ID from App Store Connect (Ex: 2X9R4HXF34)
	KeyID string
	//Is it a formal environment
	IsProduction bool
	//Parsing private keys
	PrivateKey *ecdsa.PrivateKey
	//Request client
	Client *requests.Client
}

func NewApiClient(iss, bid, keyID string, privateKey []byte, isProduction bool) (api *ApiClient, err error) {
	api = &ApiClient{Bid: bid, Iss: iss, KeyID: keyID, IsProduction: isProduction}
	api.PrivateKey, err = utility.EcdsaPrivateKey(privateKey)
	if err != nil {
		return
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	api.Client = requests.NewWithHttpClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			//DialContext: defaultTransportDialContext(),
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
		},
	})
	if api.IsProduction {
		api.Client.SetBaseURL(apiUrl)
	} else {
		api.Client.SetBaseURL(apiBoxUrl)
	}
	return
}

type CustomClaims struct {
	jwt.Claims
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Aud string `json:"aud"`
	Bid string `json:"bid"`
}

// BuildJwtToken
//https://developer.apple.com/documentation/appstoreserverapi/generating_tokens_for_api_requests
func (a *ApiClient) BuildJwtToken() (string, error) {
	claims := CustomClaims{
		Iss: a.Iss,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(5 * time.Minute).Unix(),
		Aud: "appstoreconnect-v1",
		Bid: a.Bid,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header = map[string]any{
		"alg": "ES256",
		"kid": a.KeyID,
		"typ": "JWT",
	}
	accessToken, err := token.SignedString(a.PrivateKey)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}
func (a *ApiClient) WithTokenGet(path string, data, d any) error {
	token, err := a.BuildJwtToken()
	if err != nil {
		return err
	}
	a.Client.WithToken(token)
	return a.Client.GetUnmarshal(context.Background(), path, data, d)
}
func (a *ApiClient) WithTokenPost(path string, data, d any) error {
	token, err := a.BuildJwtToken()
	if err != nil {
		return err
	}
	a.Client.WithToken(token)
	return a.Client.AsJson().PostUnmarshal(context.Background(), path, data, d)
}
func (a *ApiClient) WithTokenPut(path string, data, d any) error {
	token, err := a.BuildJwtToken()
	if err != nil {
		return err
	}
	a.Client.WithToken(token)
	return a.Client.AsJson().PutUnmarshal(context.Background(), path, data, d)
}
