package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type HealthInfo struct {
	Version       string  `json:"version"`
	Uptime        float64 `json:"uptime"`
	Pid           int     `json:"pid"`
	Backend       string  `json:"backend"`
	LastACLFetch  float64 `json:"last_acl_fetch"`
	NumGoroutines int     `json:"num_goroutines"`
}

func getCurrentHealth(backend string) *HealthInfo {
	hi := &HealthInfo{
		Version: version,
		Uptime:  math.Floor(time.Since(startTime).Seconds()),
		Pid:     os.Getpid(),
		Backend: backend,
		// LastACLFetch:  math.Floor(time.Since(aclStore.LastFetched()).Seconds()),
		NumGoroutines: runtime.NumGoroutine(),
	}

	return hi
}

func clientTCPConns(listener net.Listener) chan net.Conn {
	ch := make(chan net.Conn)
	go func() {
		for {
			client, _ := listener.Accept()
			if client == nil {
				continue
			}
			ch <- client
		}
	}()
	return ch
}

func handleTCPConn(client net.Conn, backend string) {
	b := bufio.NewReader(client)
	for {
		line, err := b.ReadString('\n')
		if err != nil { // EOF, or worse
			break
		}
		if strings.TrimSpace(line) == "healthz" {
			hi, err := json.Marshal(getCurrentHealth(backend))
			if err != nil {
				fmt.Printf(err.Error())
			}
			client.Write(append(hi, byte(0x0a)))
		}
	}
}

func healthzHandler(backend string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hi := getCurrentHealth(backend)
		encoder := json.NewEncoder(w)
		encoder.Encode(hi)
	})
}
