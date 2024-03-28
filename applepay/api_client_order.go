package applepay

import (
	"fmt"
)

// LookUpOrderId Look Up Order ID
// Doc: https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id
func (a *ApiClient) LookUpOrderId(orderId string) (resp *ResponseLookUpOrderId, err error) {
	resp = new(ResponseLookUpOrderId)
	path := fmt.Sprintf(lookUpOrderID, orderId)
	err = a.WithTokenGet(path, nil, &resp)
	return
}

type ResponseLookUpOrderId struct {
	ResponseErrorMessage
	Status             int                 `json:"status,omitempty"` // 0-valid，1-invalid
	SignedTransactions []SignedTransaction `json:"signedTransactions,omitempty"`
}
