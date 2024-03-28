## 整体流程简述

> 参考文档：https://help.apple.com/app-store-connect/#/devb57be10e7

1. app从服务端获取待支付订单ID（这个订单ID是自己服务端产生的订单信息）和待付费productId（如果在苹果上配置了多个productId，则需要从服务端拉取自己的商品和苹果商品关联信息，这里的是指在苹果的productId）；
2. app根据productId，发起应用内支付；
3. app得到支付成功结果，并将支付结果的receipt信息以及第一步的待支付订单ID发回自己的服务端，服务端调用SDK的Verify，得到校验结果（表示该支付信息是否是苹果处理的）；
4. 如果校验成功则表示苹果支付完成，根据第三步传回的订单ID来处理自己的后续业务逻辑；
 综上：当使用苹果的应用内支付时，其实是由自己的客户端APP来发起的“支付结果通知”请求来推动业务支付流程的数据流转。

## Apple

- App Store Server API：[官方文档](https://developer.apple.com/documentation/appstoreserverapi)

## Apple ApiClient

初始化Apple客户端
~~~
privateKeyByte, err := os.ReadFile(privateKeyFile)
if err != nil {
  return
}
// 初始化通联客户端
// iss：issuer ID
// bid：bundle ID
// kid：private key ID
// privateKeyFile：私钥文件读取后的字节内容
// isProduction：是否是正式环境
api, err := pay.NewApiClient(iss, bid, keyID, privateKeyByte,false)
~~~

### App Store Server API Client Function

- `client.GetTransactionInfo()` => [Get Transaction Info](https://developer.apple.com/documentation/appstoreserverapi/get_transaction_info)
- `client.GetTransactionHistory()` => [Get Transaction History](https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history)
- `client.GetAllSubscriptionStatuses()` =>[get_all_subscription_statuses](https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses)
- `client.SendConsumptionInformation()` => [Send Consumption Information](https://developer.apple.com/documentation/appstoreserverapi/send_consumption_information)
- `client.GetNotificationHistory()` => [Get Notification History](https://developer.apple.com/documentation/appstoreserverapi/get_notification_history)
- `client.LookUpOrderId()` => [Look Up Order ID](https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id)
- `client.GetRefundHistory()` => [Get Refund History](https://developer.apple.com/documentation/appstoreserverapi/get_refund_history)

### Apple Function

* `apple.VerifyReceipt()` => [验证支付凭证](https://developer.apple.com/documentation/appstorereceipts/verifyreceipt)
* `apple.ExtractClaims()` => 解析signedPayload
* `apple.DecodeSignedPayload()` => 解析notification signedPayload


## Apple支付回调用状态说明

> notificationtype: https://developer.apple.com/documentation/appstoreservernotifications/notificationtype
>
> subtype: https://developer.apple.com/documentation/appstoreservernotifications/subtype