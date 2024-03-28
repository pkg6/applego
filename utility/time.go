package utility

import (
	"strconv"
	"time"
)

func MilliStrToTime(s string) (time.Time, error) {
	t, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(t), nil
}
