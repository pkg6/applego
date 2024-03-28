package applepay

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestDecodeSignedPayload(t *testing.T) {
	file, _ := os.ReadFile("test_notification_v2_signed_payload.txt")
	payload, err := DecodeSignedPayload(string(file))
	assert.Equal(t, err, nil)
	info, err := payload.DecodeRenewalInfo()
	assert.Equal(t, err, nil)
	assert.Equal(t, info.Environment, "Sandbox")
	transactionInfo, err := payload.DecodeTransactionInfo()
	assert.Equal(t, err, nil)
	assert.Equal(t, transactionInfo.Environment, "Sandbox")
}
