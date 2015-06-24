package snmpclient2_test

import (
	"testing"

	"github.com/runner-mei/snmpclient2"
)

func TestHoge(t *testing.T) {
	expStr := "1234567890abcdef"

	str := expStr
	if expStr != snmpclient2.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}

	str = "0x" + expStr
	if expStr != snmpclient2.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}

	str = "0X" + expStr
	if expStr != snmpclient2.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}
}
