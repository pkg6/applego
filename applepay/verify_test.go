package applepay

import (
	"context"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestVerifyReceipt(t *testing.T) {
	receiptByte, _ := os.ReadFile("test_verify_receipt.txt")
	pwd := os.Getenv("APPLE_PWD")
	resp, err := VerifyReceipt(context.Background(), UrlSandbox, pwd, string(receiptByte))
	assert.Equal(t, err, nil)
	assert.Equal(t, resp.Environment, "Sandbox")
}
