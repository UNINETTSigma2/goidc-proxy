package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitCookie(t *testing.T) {
	cValue := "dummyCookie"
	assert := assert.New(t)

	cnt, cValues := splitCookie(cValue, 15)
	assert.Equal(1, cnt, "Count should be 1")
	assert.Equal([]string{"dummyCookie"}, cValues, "Cookies value must be same")

	cnt, cValues = splitCookie(cValue, 5)
	assert.Equal(3, cnt, "Count should be 3")
	assert.Equal([]string{"dummy", "Cooki", "e"}, cValues, "Cookies value must be same")
}
