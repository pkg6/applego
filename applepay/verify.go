package applepay

import (
	"context"
	"github.com/pkg6/go-requests"
)

const (
	// UrlSandbox is the URL when testing your app in the sandbox and while your application is in review
	UrlSandbox = "https://sandbox.itunes.apple.com/verifyReceipt"
	// UrlProd is the URL when your app is live in the App Store
	UrlProd = "https://buy.itunes.apple.com/verifyReceipt"
)

// VerifyReceipt 请求APP Store 校验支付请求,实际测试时发现这个文档介绍的返回信息只有那个status==0表示成功可以用，其他的返回信息跟文档对不上
// url：取 UrlProd 或 UrlSandbox
// pwd：苹果APP秘钥，https://help.apple.com/app-store-connect/#/devf341c0f01
// 文档：https://developer.apple.com/documentation/appstorereceipts/verifyreceipt
func VerifyReceipt(ctx context.Context, url, pwd, receipt string) (resp *VerifyResponse, err error) {
	req := &VerifyRequest{Receipt: receipt, Password: pwd}
	resp = new(VerifyResponse)
	err = requests.New().PostJsonUnmarshal(ctx, url, req, &resp)
	return resp, err
}
