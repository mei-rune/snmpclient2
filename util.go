package snmpclient2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var random *rand.Rand
var randOnce sync.Once

func initRandom() {
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func genRequestId() int {
	randOnce.Do(initRandom)
	return int(random.Int31())
}

func genSalt32() int32 {
	randOnce.Do(initRandom)
	return random.Int31()
}

func genSalt64() int64 {
	randOnce.Do(initRandom)
	return random.Int63()
}

var mesId int = math.MaxInt32 - 1
var mesMutex sync.Mutex

func genMessageId() (id int) {
	randOnce.Do(initRandom)
	mesMutex.Lock()
	mesId++
	if mesId == math.MaxInt32 {
		mesId = int(random.Int31())
	}
	id = mesId
	mesMutex.Unlock()
	return
}

func retry(retries int, f func() error) (err error) {
	for i := 0; i <= retries; i++ {
		err = f()
		switch err.(type) {
		case net.Error:
			if err.(net.Error).Timeout() {
				continue
			}
		case notInTimeWindowError:
			err = err.(notInTimeWindowError).ResponseError
			continue
		}
		return
	}
	return
}

func confirmedType(t PduType) bool {
	if t == GetRequest || t == GetNextRequest || t == SetRequest ||
		t == GetBulkRequest || t == InformRequest {
		return true
	}
	return false
}

func engineIdToBytes(engineId string) ([]byte, error) {
	b, err := hex.DecodeString(engineId)
	if l := len(b); err != nil || (l < 5 || l > 32) {
		return nil, ArgumentError{
			Value:   engineId,
			Message: "EngineId must be a hexadecimal string and length is range 5..32",
		}
	}
	return b, nil
}

var hexPrefix *regexp.Regexp = regexp.MustCompile(`^0[xX]`)

func StripHexPrefix(s string) string {
	return hexPrefix.ReplaceAllString(s, "")
}

func ToHexStr(a []byte, sep string) string {
	s := make([]string, len(a))
	for i, b := range a {
		s[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(s, sep)
}

func escape(s interface{}) string {
	r, _ := json.Marshal(s)
	return string(r)
}

func xor(a, b []byte) []byte {
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func padding(b []byte, size int) []byte {
	pad := size - (len(b) % size)
	if pad > 0 {
		b = append(b, bytes.Repeat([]byte{0x00}, pad)...)
	}
	return b
}

func ParseVersion(v string) (SnmpVersion, error) {
	switch v {
	case "v1", "V1", "1":
		return V1, nil
	case "v2", "V2", "v2c", "V2C", "2", "2c", "2C":
		return V2c, nil
	case "v3", "V3", "3":
		return V3, nil
	}
	return 0, errors.New("Unsupported version - " + v)
}

// For snmpgo testing
func ArgsValidate(args *Arguments) error     { return args.validate() }
func SnmpCheckPdu(snmp *SNMP, pdu PDU) error { return snmp.checkPdu(pdu) }

func NewCommunity() Security { return &community{} }
func NewUsm() Security       { return &USM{} }

func GetArgs(snmp *SNMP) *Arguments { return &snmp.args }
