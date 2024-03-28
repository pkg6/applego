package applepay

import (
	"fmt"
)

// SendConsumptionInformation Send Consumption Information
// Doc: https://developer.apple.com/documentation/appstoreserverapi/send_consumption_information
func (a *ApiClient) SendConsumptionInformation(transactionId string) (err error) {
	resp := new(ResponseErrorMessage)
	path := fmt.Sprintf(sendConsumptionInformation, transactionId)
	return a.WithTokenPut(path, nil, &resp)
}
