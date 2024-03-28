package applepay

import (
	"fmt"
)

func NotificationV2SignedPayload(signedPayload string) (resp *NotificationV2SignedPayloadResponse, err error) {
	resp = new(NotificationV2SignedPayloadResponse)
	resp.Payload, err = DecodeSignedPayload(signedPayload)
	if err != nil {
		return nil, err
	}
	resp.RenewalInfo, err = resp.Payload.DecodeRenewalInfo()
	if err != nil {
		return nil, err
	}
	resp.TransactionInfo, err = resp.Payload.DecodeTransactionInfo()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// DecodeSignedPayload 解析SignedPayload数据
func DecodeSignedPayload(signedPayload string) (payload *NotificationV2Payload, err error) {
	if signedPayload == "" {
		return nil, fmt.Errorf("signedPayload is empty")
	}
	payload = &NotificationV2Payload{}
	if err = ExtractClaims(signedPayload, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
