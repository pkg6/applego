package applepay

import (
	"errors"
	"fmt"
)

// GetAllSubscriptionStatuses Get All Subscription Statuses
// Doc: https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
func (a *ApiClient) GetAllSubscriptionStatuses(transactionId string) (resp *ResponseAllSubscriptionStatuses, err error) {
	resp = new(ResponseAllSubscriptionStatuses)
	path := fmt.Sprintf(getAllSubscriptionStatuses, transactionId)
	err = a.WithTokenGet(path, nil, &resp)
	return
}

type ResponseAllSubscriptionStatuses struct {
	ResponseErrorMessage
	AppAppleId  int                            `json:"appAppleId"`
	BundleId    string                         `json:"bundleId"`
	Environment string                         `json:"environment"`
	Data        []*AllSubscriptionStatusesData `json:"data"`
}
type AllSubscriptionStatusesData struct {
	SubscriptionGroupIdentifier string                  `json:"subscriptionGroupIdentifier"`
	LastTransactions            []*LastTransactionsItem `json:"lastTransactions"`
}
type LastTransactionsItem struct {
	OriginalTransactionId string `json:"originalTransactionId"`
	Status                int    `json:"status"`
	SignedRenewalInfo     string `json:"signedRenewalInfo"`
	SignedTransactionInfo string `json:"signedTransactionInfo"`
}

func (d *LastTransactionsItem) DecodeRenewalInfo() (ri *RenewalInfo, err error) {
	if d.SignedRenewalInfo == "" {
		return nil, errors.New("SignedRenewalInfo is empty")
	}
	ri = &RenewalInfo{}
	if err = ExtractClaims(d.SignedRenewalInfo, ri); err != nil {
		return nil, err
	}
	return ri, nil
}

func (d *LastTransactionsItem) DecodeTransactionInfo() (ti *TransactionInfo, err error) {
	if d.SignedTransactionInfo == "" {
		return nil, errors.New("signedTransactionInfo is empty")
	}
	ti = &TransactionInfo{}
	if err = ExtractClaims(d.SignedTransactionInfo, ti); err != nil {
		return nil, err
	}
	return ti, nil
}
