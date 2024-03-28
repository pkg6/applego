package utility

import (
	"encoding/json"
	"github.com/pkg6/go-requests"
	"net/url"
	"sort"
	"strings"
)

type BodyMap map[string]any

func (bm BodyMap) Set(key string, value any) BodyMap {
	bm[key] = value
	return bm
}
func (bm BodyMap) SetBodyMap(key string, value func(b BodyMap)) BodyMap {
	_bm := make(BodyMap)
	value(_bm)
	bm[key] = _bm
	return bm
}

func (bm BodyMap) Get(key string) string {
	return bm.GetString(key)
}
func (bm BodyMap) GetString(key string) string {
	if bm == nil {
		return ""
	}
	value, ok := bm[key]
	if !ok {
		return "NULL"
	}
	v, ok := value.(string)
	if !ok {
		return requests.AnyString(value)
	}
	return v
}

func (bm BodyMap) GetInterface(key string) any {
	if bm == nil {
		return nil
	}
	return bm[key]
}
func (bm BodyMap) Remove(key string) {
	delete(bm, key)
}
func (bm BodyMap) Reset() {
	for k := range bm {
		delete(bm, k)
	}
}
func (bm BodyMap) JsonBody() (jb string) {
	bs, err := json.Marshal(bm)
	if err != nil {
		return ""
	}
	jb = string(bs)
	return jb
}
func (bm BodyMap) Unmarshal(ptr any) (err error) {
	bs, err := json.Marshal(bm)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, ptr)
}
func (bm BodyMap) EncodeURLParams() string {
	if bm == nil {
		return ""
	}
	var (
		buf  strings.Builder
		keys []string
	)
	for k := range bm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := bm.GetString(k); v != "" {
			buf.WriteString(url.QueryEscape(k))
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
			buf.WriteByte('&')
		}
	}
	if buf.Len() <= 0 {
		return ""
	}
	return buf.String()[:buf.Len()-1]
}
