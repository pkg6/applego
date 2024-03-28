package applepay

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

type NotificationV2SignedPayloadResponse struct {
	Payload         *NotificationV2Payload `json:"payload"`
	RenewalInfo     *RenewalInfo           `json:"renewal_info"`
	TransactionInfo *TransactionInfo       `json:"transaction_info"`
}

// NotificationV2Payload
//https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2decodedpayload
type NotificationV2Payload struct {
	jwt.StandardClaims
	NotificationType string `json:"notificationType"`
	Subtype          string `json:"subtype"`
	NotificationUUID string `json:"notificationUUID"`
	Version          string `json:"version"`
	Data             *Data  `json:"data"`
}

// Data
//https://developer.apple.com/documentation/appstoreservernotifications/data
type Data struct {
	AppAppleID            int    `json:"appAppleId"`
	BundleID              string `json:"bundleId"`
	BundleVersion         string `json:"bundleVersion"`
	Environment           string `json:"environment"`
	SignedRenewalInfo     string `json:"signedRenewalInfo"`
	SignedTransactionInfo string `json:"signedTransactionInfo"`
}

// RenewalInfo https://developer.apple.com/documentation/appstoreservernotifications/jwsrenewalinfodecodedpayload
type RenewalInfo struct {
	jwt.StandardClaims
	AutoRenewProductId          string `json:"autoRenewProductId"`
	AutoRenewStatus             int64  `json:"autoRenewStatus"`
	Environment                 string `json:"environment"`
	ExpirationIntent            int64  `json:"expirationIntent"`
	GracePeriodExpiresDate      int64  `json:"gracePeriodExpiresDate"`
	IsInBillingRetryPeriod      bool   `json:"isInBillingRetryPeriod"`
	OfferIdentifier             string `json:"offerIdentifier"`
	OfferType                   int64  `json:"offerType"` // 1:An introductory offer. 2:A promotional offer. 3:An offer with a subscription offer code.
	OriginalTransactionId       string `json:"originalTransactionId"`
	PriceIncreaseStatus         int64  `json:"priceIncreaseStatus"` // 0: The customer hasn’t responded to the subscription price increase. 1:The customer consented to the subscription price increase.
	ProductId                   string `json:"productId"`
	RecentSubscriptionStartDate int64  `json:"recentSubscriptionStartDate"`
	RenewalDate                 int64  `json:"renewalDate,omitempty"` // The UNIX time, in milliseconds, that the most recent auto-renewable subscription purchase expires.
	SignedDate                  int64  `json:"signedDate"`
}

// TransactionInfo https://developer.apple.com/documentation/appstoreservernotifications/jwstransactiondecodedpayload
type TransactionInfo struct {
	jwt.StandardClaims
	AppAccountToken             string `json:"appAccountToken"`
	BundleId                    string `json:"bundleId"`
	Environment                 string `json:"environment"`
	ExpiresDate                 int64  `json:"expiresDate"`
	InAppOwnershipType          string `json:"inAppOwnershipType"` // FAMILY_SHARED  PURCHASED
	IsUpgraded                  bool   `json:"isUpgraded"`
	OfferIdentifier             string `json:"offerIdentifier"`
	OfferType                   int64  `json:"offerType"` // 1:An introductory offer. 2:A promotional offer. 3:An offer with a subscription offer code.
	OriginalPurchaseDate        int64  `json:"originalPurchaseDate"`
	OriginalTransactionId       string `json:"originalTransactionId"`
	ProductId                   string `json:"productId"`
	PurchaseDate                int64  `json:"purchaseDate"`
	Quantity                    int64  `json:"quantity"`
	RevocationDate              int64  `json:"revocationDate"`
	RevocationReason            int    `json:"revocationReason"`
	SignedDate                  int64  `json:"signedDate"` // Auto-Renewable Subscription: An auto-renewable subscription.  Non-Consumable: A non-consumable in-app purchase.  Consumable: A consumable in-app purchase.  Non-Renewing Subscription: A non-renewing subcription.
	SubscriptionGroupIdentifier string `json:"subscriptionGroupIdentifier"`
	TransactionId               string `json:"transactionId"`
	TransactionReason           string `json:"transactionReason"`
	Type                        string `json:"type"`
	WebOrderLineItemId          string `json:"webOrderLineItemId"`
	Storefront                  string `json:"storefront"`
	StorefrontId                string `json:"storefrontId"`
}

func (p *TransactionInfo) ExpiresDateTime() (time.Time, error) {
	return time.UnixMilli(p.ExpiresDate), nil
}
func (p *TransactionInfo) OriginalPurchaseDateTime() (time.Time, error) {
	return time.UnixMilli(p.OriginalPurchaseDate), nil
}

func (p *TransactionInfo) PurchaseDateTime() (time.Time, error) {
	return time.UnixMilli(p.PurchaseDate), nil
}
func (d *NotificationV2Payload) DecodeRenewalInfo() (ri *RenewalInfo, err error) {
	if d.Data == nil {
		return nil, fmt.Errorf("data is nil")
	}
	if d.Data.SignedRenewalInfo == "" {
		return nil, fmt.Errorf("data.signedRenewalInfo is empty")
	}
	ri = &RenewalInfo{}
	if err = ExtractClaims(d.Data.SignedRenewalInfo, ri); err != nil {
		return nil, err
	}
	return
}

func (d *NotificationV2Payload) DecodeTransactionInfo() (ti *TransactionInfo, err error) {
	if d.Data == nil {
		return nil, fmt.Errorf("data is nil")
	}
	if d.Data.SignedTransactionInfo == "" {
		return nil, fmt.Errorf("data.signedTransactionInfo is empty")
	}
	ti = &TransactionInfo{}
	if err = ExtractClaims(d.Data.SignedTransactionInfo, ti); err != nil {
		return nil, err
	}
	return
}
