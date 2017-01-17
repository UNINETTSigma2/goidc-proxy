package main

import (
	"sync"
	"time"
)

type Value struct {
	Data string
	TTL  int
}

type TTLMap struct {
	sync.RWMutex
	m map[string]Value
}

func addEntry(dataMap TTLMap, key string, value string) {
	dataMap.Lock()
	dataMap.m[key] = Value{value, 300}
	dataMap.Unlock()
}

func delEntry(dataMap TTLMap, key string) {
	dataMap.Lock()
	delete(dataMap.m, key)
	dataMap.Unlock()
}

func getEntry(dataMap TTLMap, key string) string {
	dataMap.RLock()
	v := dataMap.m[key]
	dataMap.RUnlock()
	return v.Data
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
			}
		}
		dataMap.Unlock()
	}
}
