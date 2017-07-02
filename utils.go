package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const TTL = 300

type Value struct {
	time int64
	TTL  int
}

type TTLMap struct {
	sync.RWMutex
	m map[string]Value
}

func addEntry(dataMap TTLMap, key string, value int64) {
	dataMap.Lock()
	dataMap.m[key] = Value{value, TTL}
	dataMap.Unlock()
}

func delEntry(dataMap TTLMap, key string) {
	dataMap.Lock()
	delete(dataMap.m, key)
	dataMap.Unlock()
}

func getEntry(dataMap TTLMap, key string) int64 {
	dataMap.RLock()
	v, ok := dataMap.m[key]
	dataMap.RUnlock()
	if !ok {
		return 0
	}
	return v.time
}

func expireEnteries(dataMap TTLMap) bool {
	for {
		time.Sleep(10 * time.Second)
		dataMap.Lock()
		for k, v := range dataMap.m {
			if v.TTL <= 0 {
				delete(dataMap.m, k)
			} else {
				v.TTL = v.TTL - 10
				dataMap.m[k] = v
			}
		}
		dataMap.Unlock()
	}
}

func isXHR(path string) bool {
	for _, xhrEP := range xhrEndpoints {
		if strings.HasPrefix(path, xhrEP) {
			return true
		}
	}
	return false
}

func getRedirectJS(cookieName string, url string) []byte {
	return []byte(`
		<script>
			var href = window.location.href;
			var hrefLen = href.length;
			var protoLen = window.location.protocol.length + 2; // for two slashes
			var hostLen = window.location.hostname.length;
			var cookieValue = href.substring(protoLen+hostLen, hrefLen);
			if (cookieValue.indexOf(":") === 0) {
				var cValLen = cookieValue.length;
				cookieValue = cookieValue.substring(cookieValue.indexOf("/"), cValLen)
			}
			var date = new Date();
			date.setTime(date.getTime()+(28800*1000));
			var expires = "; expires="+date.toString();
			var cookieName = "` + cookieName + `";
			document.cookie = cookieName+"="+encodeURIComponent(cookieValue)+expires+"; path=/";
			window.location = "` + url + `";
		</script>
	`)
}

func GetIPsFromRequest(r *http.Request) []string {
	var ips []string
	for _, ip := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		trimmed := strings.TrimSpace(ip)
		if trimmed != "" {
			ips = append(ips, trimmed)
		}
	}
	if r.RemoteAddr != "" {
		ips = append(ips, strings.Trim(r.RemoteAddr[:strings.LastIndex(r.RemoteAddr, ":")], "[]"))
	}
	return ips
}

func splitCookie(cValue string, chunkLen int) (int, []string) {
	cnt := 0
	var cValues []string
	for i := 0; len(cValue) > chunkLen; i = i + chunkLen {
		cnt += 1
		cValues = append(cValues, cValue[:chunkLen])
		cValue = cValue[chunkLen:]
	}
	if len(cValue) > 0 {
		cValues = append(cValues, cValue)
		cnt += 1
	}
	return cnt, cValues
}

func readCookie(r *http.Request, cName string) (string, error) {
	i := 0
	var cValue string
	for {
		cookie, err := r.Cookie(cName + strconv.Itoa(i))
		if err == nil {
			cValue += cookie.Value
		} else {
			break
		}
		i += 1
	}
	if cValue == "" {
		return "", errors.New("Failed in reading cookie")
	}
	return cValue, nil
}
