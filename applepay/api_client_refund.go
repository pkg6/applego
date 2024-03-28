package applepay

import (
	"fmt"
)

// GetRefundHistory Get Refund History
// Doc: https://developer.apple.com/documentation/appstoreserverapi/get_refund_history
func (a *ApiClient) GetRefundHistory(transactionId, revision string) (rsp *ResponseRefundHistory, err error) {
	resp := new(ResponseRefundHistory)
	path := fmt.Sprintf(getRefundHistory, transactionId) + "?revision=" + revision
	err = a.WithTokenGet(path, nil, &resp)
	return
}

type ResponseRefundHistory struct {
	ResponseErrorMessage
	HasMore            bool                `json:"hasMore"`
	Revision           string              `json:"revision"`
	SignedTransactions []SignedTransaction `json:"signedTransactions"`
}
