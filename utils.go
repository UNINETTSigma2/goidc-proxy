package main

import (
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
			if (cookieValue.startsWith(":")) {
				var cValLen = cookieValue.length;
				cookieValue = cookieValue.substring(cookieValue.indexOf("/"), cValLen)
			}
			var date = new Date();
			date.setTime(date.getTime()+(28800*1000));
			var expires = "; expires="+date.toString();
			var cookieName = "` + cookieName + `";
			document.cookie = cookieName+"="+cookieValue+expires+"; path=/";
			window.location = "` + url + `";
		</script>
	`)
}
