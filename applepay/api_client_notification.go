package applepay

// GetNotificationHistory Get Notification History
// rsp.NotificationHistory[x].SignedPayload use apple.DecodeSignedPayload() to decode
// Doc: https://developer.apple.com/documentation/appstoreserverapi/get_notification_history
func (a *ApiClient) GetNotificationHistory(paginationToken string) (resp *ResponseNotificationHistory, err error) {
	resp = new(ResponseNotificationHistory)
	path := getNotificationHistory
	if paginationToken != "" {
		path += "?paginationToken=" + paginationToken
	}
	err = a.WithTokenPost(path, nil, &resp)
	return
}

type ResponseNotificationHistory struct {
	ResponseErrorMessage
	HasMore             bool                `json:"hasMore"`
	PaginationToken     string              `json:"paginationToken"`
	NotificationHistory []*NotificationItem `json:"notificationHistory"`
}
type NotificationItem struct {
	SendAttempts  []*SendAttemptItem `json:"sendAttempts"`
	SignedPayload string             `json:"signedPayload"`
}
type SendAttemptItem struct {
	AttemptDate       int64  `json:"attemptDate"`
	SendAttemptResult string `json:"sendAttemptResult"`
}
