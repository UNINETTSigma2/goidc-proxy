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
	// aria-hidden is to avoid screen readers blurting out technical details on this page.
	return []byte(`
<!DOCTYPE html>
<html lang="en">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>OAuth Authentication redirect</title>
<style type="text/css">
	.spinner:after {
		animation-duration: .4s;
		animation-name: spin;
		animation-iteration-count: infinite;
	}
	@keyframes spin {
		0%% {content: "/";}
		25%% {content: "-";}
		50%% {content: "\\";}
		75%% {content: "|";}
		100%% {content: "/";}
	}
</style>

<pre id="loading" style="display:none" aria-hidden="true">You are being redirected <span class="spinner"></span></pre>
<pre id="explaination">You seem to have JavaScript disabled

This page uses JavaScript to redirect you to a login page.
The use of JavaScript is needed to keep the fragment in the URL intact. (the part after #)

Please enable JavaScript and reload this page to use this web application.
</pre>

<script type="application/javascript">
	// Hide the JavaScript message, since JavaScript clearly works.
	document.getElementById('explaination').style.display = 'none';
	document.getElementById('explaination').setAttribute('aria-hidden', true);
	document.getElementById('loading').style = 'block';

	// Get the current path from the address bar.
	// The path is everything from the third slash,
	// where the second and third slash cannot be continguous,
	// so file:/// URLs won't work.

	// http  ://  example.com /foo/bar#fragment
	//      :\/\/   [^\/]+          (\/.*)     $
	var path = window.location.href.match(/:\/\/[^\/]+(\/.*)$/)[1];

	// Format the expiry string in the cookie.
	var expiryDate = new Date();
	expiryDate.setTime(expiryDate.getTime() + 28800 * 1000);
	var expiryString = "; expires=" + expiryDate.toString();

	// Write the cookie and redirect to login page.
	document.cookie = "` + cookieName + `" + "=" + encodeURIComponent(path) + expiryString + "; path=/";
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
