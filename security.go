package snmpclient2

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math"
	"strconv"
	"time"

	"github.com/runner-mei/snmpclient2/asn1"
)

// AuthProtocol describes the authentication protocol in use by an authenticated SnmpV3 connection.
type AuthProtocol uint8

// NoAuth, MD5, and SHA are implemented
const (
	NoAuth AuthProtocol = 1
	MD5    AuthProtocol = 2
	SHA    AuthProtocol = 3
	SHA224 AuthProtocol = 4
	SHA256 AuthProtocol = 5
	SHA384 AuthProtocol = 6
	SHA512 AuthProtocol = 7
)

var (
	_ json.Marshaler   = NoAuth
	_ json.Unmarshaler = new(AuthProtocol)
)

func (protoc AuthProtocol) MarshalJSON() ([]byte, error) {
	switch protoc {
	case NoAuth:
		return []byte(`"NoAuth"`), nil
	case MD5:
		return []byte(`"MD5"`), nil
	case SHA:
		return []byte(`"SHA"`), nil
	case SHA224:
		return []byte(`"SHA224"`), nil
	case SHA256:
		return []byte(`"SHA256"`), nil
	case SHA384:
		return []byte(`"SHA384"`), nil
	case SHA512:
		return []byte(`"SHA512"`), nil
	}
	return nil, errors.New("AuthProtocol '" + strconv.FormatInt(int64(protoc), 10) + "' is unsupported.")
}

func (protoc *AuthProtocol) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("noauth")) || bytes.Equal(data, []byte(`"noauth"`)) ||
		bytes.Equal(data, []byte("noAuth")) || bytes.Equal(data, []byte(`"noAuth"`)) ||
		bytes.Equal(data, []byte("NoAuth")) || bytes.Equal(data, []byte(`"NoAuth"`)) ||
		bytes.Equal(data, []byte("NOAUTH")) || bytes.Equal(data, []byte(`"NOAUTH"`)) {
		*protoc = NoAuth
	} else if bytes.Equal(data, []byte("md5")) || bytes.Equal(data, []byte("MD5")) ||
		bytes.Equal(data, []byte(`"md5"`)) || bytes.Equal(data, []byte(`"MD5"`)) {
		*protoc = MD5
	} else if bytes.Equal(data, []byte("sha")) || bytes.Equal(data, []byte("SHA")) ||
		bytes.Equal(data, []byte(`"sha"`)) || bytes.Equal(data, []byte(`"SHA"`)) {
		*protoc = SHA
	} else if bytes.Equal(data, []byte("sha224")) || bytes.Equal(data, []byte("SHA224")) ||
		bytes.Equal(data, []byte(`"sha224"`)) || bytes.Equal(data, []byte(`"SHA224"`)) {
		*protoc = SHA224
	} else if bytes.Equal(data, []byte("sha256")) || bytes.Equal(data, []byte("SHA256")) ||
		bytes.Equal(data, []byte(`"sha256"`)) || bytes.Equal(data, []byte(`"SHA256"`)) {
		*protoc = SHA256
	} else if bytes.Equal(data, []byte("sha384")) || bytes.Equal(data, []byte("SHA384")) ||
		bytes.Equal(data, []byte(`"sha384"`)) || bytes.Equal(data, []byte(`"SHA384"`)) {
		*protoc = SHA384
	} else if bytes.Equal(data, []byte("sha512")) || bytes.Equal(data, []byte("SHA512")) ||
		bytes.Equal(data, []byte(`"sha512"`)) || bytes.Equal(data, []byte(`"SHA512"`)) {
		*protoc = SHA512
	} else {
		return errors.New("AuthProtocol '" + string(data) + "' is unsupported")
	}
	return nil
}

//go:generate stringer -type=AuthProtocol

func (protoc AuthProtocol) AuthParameterLength() int {
	return macVarbinds[protoc].length
}

func (protoc AuthProtocol) validate() bool {
	return protoc == MD5 ||
		protoc == SHA ||
		protoc == SHA224 ||
		protoc == SHA256 ||
		protoc == SHA384 ||
		protoc == SHA512
}

// HashType maps the AuthProtocol's hash type to an actual crypto.Hash object.
func (authProtocol AuthProtocol) HashType() crypto.Hash {
	switch authProtocol {
	case MD5:
		return crypto.MD5
	case SHA:
		return crypto.SHA1
	case SHA224:
		return crypto.SHA224
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512
	default:
		return crypto.MD5
	}
}

//nolint:gochecknoglobals
var macVarbinds = []struct {
	length int
}{
	{},
	{length: 0},
	{length: 12},
	{length: 12},
	{length: 16},
	{length: 24},
	{length: 32},
	{length: 48},
}

// PrivProtocol is the privacy protocol in use by an private SnmpV3 connection.
type PrivProtocol uint8

// NoPriv, DES implemented, AES planned
// Changed: AES192, AES256, AES192C, AES256C added
const (
	NoPriv  PrivProtocol = 1
	DES     PrivProtocol = 2
	AES     PrivProtocol = 3
	AES192  PrivProtocol = 4 // Blumenthal-AES192
	AES256  PrivProtocol = 5 // Blumenthal-AES256
	AES192C PrivProtocol = 6 // Reeder-AES192
	AES256C PrivProtocol = 7 // Reeder-AES256
)

var (
	_ json.Marshaler   = NoPriv
	_ json.Unmarshaler = new(PrivProtocol)
)

//go:generate stringer -type=PrivProtocol

func (protoc PrivProtocol) validate() bool {
	return protoc == DES ||
		protoc == AES ||
		protoc == AES192 ||
		protoc == AES256 ||
		protoc == AES192C ||
		protoc == AES256C
}

func (protoc PrivProtocol) MarshalJSON() ([]byte, error) {
	switch protoc {
	case NoPriv:
		return []byte(`"NoPriv"`), nil
	case DES:
		return []byte(`"DES"`), nil
	case AES:
		return []byte(`"AES"`), nil
	case AES192:
		return []byte(`"AES192"`), nil
	case AES256:
		return []byte(`"AES256"`), nil
	case AES192C:
		return []byte(`"AES192C"`), nil
	case AES256C:
		return []byte(`"AES256C"`), nil
	}
	return nil, errors.New("PrivProtocol '" + strconv.FormatInt(int64(protoc), 10) + "' is unsupported.")
}

func (protoc *PrivProtocol) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("nopriv")) || bytes.Equal(data, []byte(`"nopriv"`)) ||
		bytes.Equal(data, []byte("noPriv")) || bytes.Equal(data, []byte(`"noPriv"`)) ||
		bytes.Equal(data, []byte("NoPriv")) || bytes.Equal(data, []byte(`"NoPriv"`)) ||
		bytes.Equal(data, []byte("NOPRIV")) || bytes.Equal(data, []byte(`"NOPRIV"`)) {
		*protoc = NoPriv
	} else if bytes.Equal(data, []byte("des")) || bytes.Equal(data, []byte("DES")) ||
		bytes.Equal(data, []byte(`"des"`)) || bytes.Equal(data, []byte(`"DES"`)) {
		*protoc = DES
	} else if bytes.Equal(data, []byte("aes")) || bytes.Equal(data, []byte("AES")) ||
		bytes.Equal(data, []byte(`"aes"`)) || bytes.Equal(data, []byte(`"AES"`)) {
		*protoc = AES
	} else if bytes.Equal(data, []byte("aes192")) || bytes.Equal(data, []byte("AES192")) ||
		bytes.Equal(data, []byte(`"aes192"`)) || bytes.Equal(data, []byte(`"AES192"`)) {
		*protoc = AES192
	} else if bytes.Equal(data, []byte("aes256")) || bytes.Equal(data, []byte("AES256")) ||
		bytes.Equal(data, []byte(`"aes256"`)) || bytes.Equal(data, []byte(`"AES256"`)) {
		*protoc = AES256
	} else if bytes.Equal(data, []byte("aes192c")) || bytes.Equal(data, []byte("AES192C")) ||
		bytes.Equal(data, []byte(`"aes192c"`)) || bytes.Equal(data, []byte(`"AES192C"`)) {
		*protoc = AES192C
	} else if bytes.Equal(data, []byte("aes256c")) || bytes.Equal(data, []byte("AES256C")) ||
		bytes.Equal(data, []byte(`"aes256c"`)) || bytes.Equal(data, []byte(`"AES256C"`)) {
		*protoc = AES256C
	} else {
		return errors.New("PrivProtocol '" + string(data) + "' is unsupported")
	}
	return nil
}

type SecurityLevel int

const (
	NoAuthNoPriv SecurityLevel = iota
	AuthNoPriv
	AuthPriv
)

func (s SecurityLevel) String() string {
	switch s {
	case NoAuthNoPriv:
		return "NoAuthNoPriv"
	case AuthNoPriv:
		return "AuthNoPriv"
	case AuthPriv:
		return "AuthPriv"
	default:
		return "Unknown"
	}
}

type Security interface {
	GenerateRequestMessage(*Arguments, Message) error
	ProcessIncomingMessage(*Arguments, Message) error
	//Discover(*Arguments) error
	String() string
}

type community struct{}

func (c *community) GenerateRequestMessage(args *Arguments, sendMsg Message) error {
	m := sendMsg.(*MessageV1)
	m.Community = []byte(args.Community)

	if len(m.pduBytes) != 0 && m.PDU() == nil {
		return nil
	}
	b, err := m.PDU().Marshal()
	if err != nil {
		return err
	}
	m.SetPduBytes(b)
	return nil
}

func (c *community) ProcessIncomingMessage(args *Arguments, recvMsg Message) (err error) {
	rm := recvMsg.(*MessageV1)

	// if !bytes.Equal([]byte(args.Community), rm.Community) {
	// 	return ResponseError{
	// 		Message: fmt.Sprintf(
	// 			"Community mismatch - expected [%s], actual [%s]",
	// 			string(args.Community), string(rm.Community)),
	// 		Detail: fmt.Sprintf("%s vs %s", args, rm),
	// 	}
	// }

	_, err = rm.PDU().Unmarshal(rm.PduBytes())
	if err != nil {
		return ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal PDU",
			Detail:  fmt.Sprintf("PDU Bytes - [%s]", ToHexStr(rm.PduBytes(), " ")),
		}
	}
	return
}

// func (c *community) Discover(args *Arguments) error {
// 	return nil
// }

func (c *community) String() string {
	return "{}"
}

//type DiscoveryStatus int

// const (
// 	NoDiscovered DiscoveryStatus = iota
// 	NoSynchronized
// 	Discovered
// )

// func (d DiscoveryStatus) String() string {
// 	switch d {
// 	case noDiscovered:
// 		return "noDiscovered"
// 	case noSynchronized:
// 		return "noSynchronized"
// 	case discovered:
// 		return "discovered"
// 	default:
// 		return "Unknown"
// 	}
// }

type USM struct {
	//DiscoveryStatus DiscoveryStatus
	AuthEngineId    []byte
	AuthEngineBoots int64
	AuthEngineTime  int64
	// AuthKey         []byte
	// PrivKey         []byte
	UpdatedTime time.Time
}

func (u *USM) IsDiscover() bool {
	return len(u.AuthEngineId) > 0 && u.AuthEngineTime > 0
}

func (u *USM) GenerateRequestMessage(args *Arguments, sendMsg Message) (err error) {
	// setup message
	m := sendMsg.(*MessageV3)

	// // DEBUG BEGIN
	// if 14348 != m.MessageId {
	m.MessageId = m.pdu.RequestId()
	// }
	// // DEBUG END
	if args.MessageMaxSize > 256 {
		m.MessageMaxSize = args.MessageMaxSize
	} else {
		m.MessageMaxSize = 65507
	}
	m.SecurityModel = securityUsm

	m.SetReportable(confirmedType(m.pdu.PduType()))
	if args.SecurityLevel >= AuthNoPriv {
		m.SetAuthentication(true)
		if args.SecurityLevel >= AuthPriv {
			m.SetPrivacy(true)
		}
	}

	//if u.DiscoveryStatus > NoDiscovered {
	m.UserName = []byte(args.UserName)
	m.AuthEngineId = u.AuthEngineId
	//}
	// if u.DiscoveryStatus > NoSynchronized {
	err = u.UpdateEngineBootsTime()
	if err != nil {
		return err
	}
	m.AuthEngineBoots = u.AuthEngineBoots
	m.AuthEngineTime = u.AuthEngineTime
	//}

	// setup PDU
	p := sendMsg.PDU().(*ScopedPdu)

	if args.ContextEngineId != "" {
		p.ContextEngineId, _ = engineIdToBytes(args.ContextEngineId)
	} else {
		p.ContextEngineId = m.AuthEngineId
	}
	if args.ContextName != "" {
		p.ContextName = []byte(args.ContextName)
	}

	pduBytes, err := p.Marshal()
	if err != nil {
		return
	}
	m.SetPduBytes(pduBytes)

	if m.Authentication() {
		// encrypt PDU
		if m.Privacy() {
			privKey := args.PrivKey
			if len(privKey) == 0 {
				privKey, err = GenlocalPrivKey(args.PrivProtocol, args.AuthProtocol, args.PrivPassword, u.AuthEngineId)
				if err != nil {
					return err
				}
			}

			// fmt.Printf("%x\r\n", privKey)

			err = encrypt(m, args.PrivProtocol, privKey)
			if err != nil {
				fmt.Println(err)
				return err
			}
		}

		authKey := args.AuthKey
		if len(authKey) == 0 {
			authKey, err = PasswordToKey(args.AuthProtocol, args.AuthPassword, u.AuthEngineId)
			if err != nil {
				return err
			}
		}

		// fmt.Println(args.UserName, args.AuthProtocol, args.AuthPassword, fmt.Sprintf("%x", u.AuthEngineId), fmt.Sprintf("%x", authKey))

		// get digest of whole message
		digest, err := hMAC(m, args.AuthProtocol, authKey)
		if err != nil {
			return err
		}
		m.AuthParameter = digest
	}

	return nil
}

func (u *USM) ProcessIncomingMessage(args *Arguments, recvMsg Message) (err error) {
	//sm := sendMsg.(*MessageV3)
	rm := recvMsg.(*MessageV3)

	// RFC3411 Section 5
	if l := len(rm.AuthEngineId); l < 5 || l > 32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineId length is range 5..32, value [%s]",
				ToHexStr(rm.AuthEngineId, "")),
		}
	}
	if rm.AuthEngineBoots < 0 || rm.AuthEngineBoots > math.MaxInt32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineBoots is range %d..%d, value [%d]",
				0, math.MaxInt32, rm.AuthEngineBoots),
		}
	}
	if rm.AuthEngineTime < 0 || rm.AuthEngineTime > math.MaxInt32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineTime is range %d..%d, value [%d]",
				0, math.MaxInt32, rm.AuthEngineTime),
		}
	}
	// if u.DiscoveryStatus > noDiscovered {
	// 	if !bytes.Equal(u.AuthEngineId, rm.AuthEngineId) {
	// 		return ResponseError{
	// 			Message: fmt.Sprintf(
	// 				"AuthEngineId mismatch - expected [%s], actual [%s]",
	// 				ToHexStr(u.AuthEngineId, ""), ToHexStr(rm.AuthEngineId, "")),
	// 			Detail: fmt.Sprintf("%s vs %s", args, rm),
	// 		}
	// 	}
	// 	if !bytes.Equal([]byte(args.UserName), rm.UserName) {
	// 		return ResponseError{
	// 			Message: fmt.Sprintf(
	// 				"UserName mismatch - expected [%s], actual [%s]",
	// 				args.UserName, string(rm.UserName)),
	// 			Detail: fmt.Sprintf("%s vs %s", args, rm),
	// 		}
	// 	}
	// }

	if rm.Authentication() {
		//    authKey := args.AuthKey
		//		if len(authKey) == 0 {
		//			authKey = PasswordToKey(args.AuthProtocol, args.AuthPassword, u.AuthEngineId)
		//		}

		// get & check digest of whole message
		// digest, e := hMAC(rm, args.AuthProtocol, u.AuthKey)
		// if e != nil {
		// 	return ResponseError{
		// 		Cause:   e,
		// 		Message: "Can't get a message digest",
		// 	}
		// }
		// if !hmac.Equal(rm.AuthParameter, digest) {
		// 	return ResponseError{
		// 		Message: fmt.Sprintf("Failed to authenticate - expected [%s], actual [%s]",
		// 			ToHexStr(rm.AuthParameter, ""), ToHexStr(digest, "")),
		// 	}
		// }

		// decrypt PDU
		if rm.Privacy() {
			var e error
			privKey := args.PrivKey
			if len(privKey) == 0 {
				privKey, e = GenlocalPrivKey(args.PrivProtocol, args.AuthProtocol, args.PrivPassword, u.AuthEngineId)
				if e != nil {
					return ResponseError{
						Cause:   e,
						Message: "PasswordToKey fail",
					}
				}
			}

			// PrivKey := PasswordToKey(args.AuthProtocol, args.PrivPassword, u.AuthEngineId)
			e = decrypt(rm, args.PrivProtocol, privKey, rm.PrivParameter)
			if e != nil {
				return ResponseError{
					Cause:   e,
					Message: "Can't decrypt a message",
				}
			}
		}
	}

	// // update boots & time
	// switch u.DiscoveryStatus {
	// case discovered:
	// 	if rm.Authentication() {
	// 		err = u.CheckTimeliness(rm.AuthEngineBoots, rm.AuthEngineTime)
	// 		if err != nil {
	// 			u.SynchronizeEngineBootsTime(0, 0)
	// 			u.DiscoveryStatus = noSynchronized
	// 			return
	// 		}
	// 	}
	// 	fallthrough
	// case noSynchronized:
	// 	if rm.Authentication() {
	// 		u.SynchronizeEngineBootsTime(rm.AuthEngineBoots, rm.AuthEngineTime)
	// 		u.DiscoveryStatus = discovered
	// 	}
	// case noDiscovered:
	// 	u.SetAuthEngineId(args, rm.AuthEngineId)
	// 	u.DiscoveryStatus = noSynchronized
	// }

	_, err = rm.PDU().Unmarshal(rm.PduBytes())
	if err != nil {
		var note string
		if rm.Privacy() {
			note = " (probably PDU was unable to decrypt)"
		}
		return ResponseError{
			Cause:   err,
			Message: fmt.Sprintf("Failed to Unmarshal PDU%s", note),
			Detail:  fmt.Sprintf("PDU Bytes - [%s]", ToHexStr(rm.PduBytes(), " ")),
		}
	}
	p := rm.PDU().(*ScopedPdu)

	if p.PduType() == GetResponse {
		// var cxtId []byte
		// if args.ContextEngineId != "" {
		// 	cxtId, _ = engineIdToBytes(args.ContextEngineId)
		// } else {
		// 	cxtId = u.AuthEngineId
		// }
		// if !bytes.Equal(cxtId, p.ContextEngineId) {
		// 	return ResponseError{
		// 		Message: fmt.Sprintf("ContextEngineId mismatch - expected [%s], actual [%s]",
		// 			ToHexStr(cxtId, ""), ToHexStr(p.ContextEngineId, "")),
		// 	}
		// }
		// if name := args.ContextName; name != string(p.ContextName) {
		// 	return ResponseError{
		// 		Message: fmt.Sprintf("ContextName mismatch - expected [%s], actual [%s]",
		// 			name, string(p.ContextName)),
		// 	}
		// }
		// if sm.Authentication() && !rm.Authentication() {
		// 	return ResponseError{
		// 		Message: "Response message is not authenticated",
		// 	}
		// }
	}
	return
}

// func (u *USM) SetAuthEngineId(args *Arguments, authEngineId []byte) {
// 	u.AuthEngineId = authEngineId
// 	if len(args.AuthPassword) > 0 {
// 		u.AuthKey = PasswordToKey(args.AuthProtocol, args.AuthPassword, authEngineId)
// 	}
// 	if len(args.PrivPassword) > 0 {
// 		u.PrivKey = PasswordToKey(args.AuthProtocol, args.PrivPassword, authEngineId)
// 	}
// }

func (u *USM) UpdateEngineBootsTime() error {
	now := time.Now()
	u.AuthEngineTime += int64(now.Sub(u.UpdatedTime).Seconds())
	if u.AuthEngineTime > math.MaxInt32 {
		u.AuthEngineBoots++
		// RFC3414 2.2.2
		if u.AuthEngineBoots == math.MaxInt32 {
			return fmt.Errorf("EngineBoots reached the max value, [%d]", math.MaxInt32)
		}
		u.AuthEngineTime -= math.MaxInt32
	}
	u.UpdatedTime = now
	return nil
}

func (u *USM) SynchronizeEngineBootsTime(engineBoots, engineTime int64) {
	u.AuthEngineBoots = engineBoots
	u.AuthEngineTime = engineTime
	u.UpdatedTime = time.Now()
}

func (u *USM) CheckTimeliness(engineBoots, engineTime int64) error {
	// RFC3414 Section 3.2 7) b)
	if engineBoots == math.MaxInt32 ||
		engineBoots < u.AuthEngineBoots ||
		(engineBoots == u.AuthEngineBoots && engineTime-u.AuthEngineTime > 150) {
		return ResponseError{
			Message: fmt.Sprintf(
				"The message is not in the time window - local [%d/%d], remote [%d/%d]",
				engineBoots, engineTime, u.AuthEngineBoots, u.AuthEngineTime),
		}
	}
	return nil
}

func (u *USM) String() string {
	return fmt.Sprintf(
		`{"AuthEngineId": "%s", "AuthEngineBoots": "%d", `+
			`"AuthEngineTime": "%d", "UpdatedTime": "%s"}`,
		ToHexStr(u.AuthEngineId, ""), u.AuthEngineBoots, u.AuthEngineTime,
		u.UpdatedTime)
}

func hMAC(msg *MessageV3, proto AuthProtocol, key []byte) ([]byte, error) {
	authParameterLength := proto.AuthParameterLength()
	tmp := msg.AuthParameter
	msg.AuthParameter = padding([]byte{}, authParameterLength)
	msgBytes, err := msg.Marshal()
	msg.AuthParameter = tmp
	if err != nil {
		return nil, err
	}

	// fmt.Println("=========")
	// fmt.Println(ToHexStr(msgBytes, ""))

	var h hash.Hash
	switch proto {
	case MD5:
		h = hmac.New(md5.New, key)
	case SHA:
		h = hmac.New(sha1.New, key)
	case SHA224:
		h = hmac.New(crypto.SHA224.New, key)
	case SHA256:
		h = hmac.New(crypto.SHA256.New, key)
	case SHA384:
		h = hmac.New(crypto.SHA384.New, key)
	case SHA512:
		h = hmac.New(crypto.SHA512.New, key)
	default:
		return nil, errors.New("'" + fmt.Sprint(proto) + "' is unsupported hash.")
	}

	h.Write(msgBytes)
	return h.Sum(nil)[:authParameterLength], nil
}

func encrypt(msg *MessageV3, proto PrivProtocol, key []byte) (err error) {
	var dst, priv []byte
	src := msg.PduBytes()

	switch proto {
	case DES:
		dst, priv, err = EncryptDES(src, key, int32(msg.AuthEngineBoots), genSalt32())
	case AES, AES192, AES256:
		dst, priv, err = EncryptAES(
			src, key, int32(msg.AuthEngineBoots), int32(msg.AuthEngineTime), genSalt64())
	default:
		err = errors.New("'" + fmt.Sprint(proto) + "' is unsupported crypto.")
	}
	if err != nil {
		return
	}

	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, IsCompound: false}
	raw.Bytes = dst
	dst, err = asn1.Marshal(raw)
	if err == nil {
		msg.SetPduBytes(dst)
		msg.PrivParameter = priv
	}
	return
}

func decrypt(msg *MessageV3, proto PrivProtocol, key, privParam []byte) (err error) {
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(msg.PduBytes(), &raw)
	if err != nil {
		return
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagOctetString || raw.IsCompound {
		return asn1.StructuralError{fmt.Sprintf(
			"Invalid encrypted PDU object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(msg.PduBytes(), " "))}
	}

	var dst []byte
	switch proto {
	case DES:
		dst, err = DecryptDES(raw.Bytes, key, privParam)
	case AES, AES192, AES256:
		dst, err = DecryptAES(
			raw.Bytes, key, privParam, int32(msg.AuthEngineBoots), int32(msg.AuthEngineTime))
	default:
		err = errors.New("'" + fmt.Sprint(proto) + "' is unsupported crypto.")
	}

	if err == nil {
		msg.SetPduBytes(dst)
	}
	return
}

func EncryptDES(src, key []byte, engineBoots, salt int32) (dst, privParam []byte, err error) {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		return
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, engineBoots)
	binary.Write(&buf, binary.BigEndian, salt)
	privParam = buf.Bytes()
	iv := xor(key[8:16], privParam)

	src = padding(src, des.BlockSize)
	dst = make([]byte, len(src))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return
}

func DecryptDES(src, key, privParam []byte) (dst []byte, err error) {
	if len(src)%des.BlockSize != 0 {
		err = ArgumentError{
			Value:   len(src),
			Message: "Invalid DES cipher length",
		}
		return
	}
	if len(privParam) != 8 {
		err = ArgumentError{
			Value:   len(privParam),
			Message: "Invalid DES PrivParameter length",
		}
		return
	}

	block, err := des.NewCipher(key[:8])
	if err != nil {
		return
	}

	iv := xor(key[8:16], privParam)
	dst = make([]byte, len(src))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return
}

func EncryptAES(src, key []byte, engineBoots, engineTime int32, salt int64) (
	dst, privParam []byte, err error) {

	// fmt.Printf("src=%x\r\n", src)
	// fmt.Printf("key=%x\r\n", key)
	// fmt.Printf("key16=%x\r\n", key[:16])
	// fmt.Printf("engineBoots=%d\r\n", engineBoots)
	// fmt.Printf("engineTime=%d\r\n", engineTime)
	// fmt.Printf("salt=%d\r\n", salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	var buf1, buf2 bytes.Buffer
	binary.Write(&buf1, binary.BigEndian, salt)
	privParam = buf1.Bytes()

	binary.Write(&buf2, binary.BigEndian, engineBoots)
	binary.Write(&buf2, binary.BigEndian, engineTime)
	iv := append(buf2.Bytes(), privParam...)

	src = padding(src, aes.BlockSize)
	dst = make([]byte, len(src))

	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(dst, src)

	// fmt.Printf("dst=%x\r\n", dst)
	// fmt.Printf("privParam=%x\r\n", privParam)
	return
}

func DecryptAES(src, key, privParam []byte, engineBoots, engineTime int32) (
	dst []byte, err error) {

	if len(privParam) != 8 {
		err = ArgumentError{
			Value:   len(privParam),
			Message: "Invalid AES PrivParameter length",
		}
		return
	}

	// fmt.Printf("src=%x\r\n", src)
	// fmt.Printf("key=%x\r\n", key)
	// fmt.Printf("key16=%x\r\n", key[:16])
	// fmt.Printf("engineBoots=%d\r\n", engineBoots)
	// fmt.Printf("engineTime=%d\r\n", engineTime)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, engineBoots)
	binary.Write(&buf, binary.BigEndian, engineTime)
	iv := append(buf.Bytes(), privParam...)

	dst = make([]byte, len(src))

	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(dst, src)
	return
}

// // Extending the localized privacy key according to Reeder Key extension algorithm:
// // https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3dese
// // Many vendors, including Cisco, use the 3DES key extension algorithm to extend the privacy keys that are too short when using AES,AES192 and AES256.
// // Previously implemented in net-snmp and pysnmp libraries.
// // Tested for AES128 and AES256
// func extendKeyReeder(authProtocol SnmpV3AuthProtocol, password string, engineID string) ([]byte, error) {
//   var key []byte
//   var err error

//   key, err = hMAC(authProtocol.HashType(), cacheKey(authProtocol, password), password, engineID)

//   if err != nil {
//     return nil, err
//   }

//   newkey, err := hMAC(authProtocol.HashType(), cacheKey(authProtocol, string(key)), string(key), engineID)

//   return append(key, newkey...), err
// }

// // Extending the localized privacy key according to Blumenthal key extension algorithm:
// // https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#page-7
// // Not many vendors use this algorithm.
// // Previously implemented in the net-snmp and pysnmp libraries.
// // TODO: Not tested
// func extendKeyBlumenthal(authProtocol SnmpV3AuthProtocol, password string, engineID string) ([]byte, error) {
//   var key []byte
//   var err error

//   key, err = hMAC(authProtocol.HashType(), cacheKey(authProtocol, password), password, engineID)

//   if err != nil {
//     return nil, err
//   }

//   newkey := authProtocol.HashType().New()
//   _, _ = newkey.Write(key)
//   return append(key, newkey.Sum(nil)...), err
// }

// Changed: New function to calculate the Privacy Key for abstract AES
func GenlocalPrivKey(privProtocol PrivProtocol, authProtocol AuthProtocol, password string, engineID []byte) ([]byte, error) {
	var keylen int
	var localPrivKey []byte
	var err error

	switch privProtocol {
	case AES, DES:
		keylen = 16
	case AES192, AES192C:
		keylen = 24
	case AES256, AES256C:
		keylen = 32
	}

	switch privProtocol {
	case AES, AES192C, AES256C:
		localPrivKey, err = extendKeyReeder(authProtocol, password, engineID)
	case AES192, AES256:
		localPrivKey, err = extendKeyBlumenthal(authProtocol, password, engineID)
	default:
		localPrivKey, err = PasswordToKey(authProtocol, password, engineID)
	}
	if err != nil {
		return nil, err
	}

	if len(localPrivKey) < keylen {
		return nil, fmt.Errorf("genlocalPrivKey: privProtocol: %v len(localPrivKey): %d, keylen: %d",
			privProtocol, len(localPrivKey), keylen)
	}

	return localPrivKey[:keylen], nil
}

// Extending the localized privacy key according to Reeder Key extension algorithm:
// https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3dese
// Many vendors, including Cisco, use the 3DES key extension algorithm to extend the privacy keys that are too short when using AES,AES192 and AES256.
// Previously implemented in net-snmp and pysnmp libraries.
// Tested for AES128 and AES256
func extendKeyReeder(authProtocol AuthProtocol, password string, engineID []byte) ([]byte, error) {
	key, err := PasswordToKey(authProtocol, password, engineID)
	if err != nil {
		return nil, err
	}
	newkey, err := passwordToKey(authProtocol, key, engineID)
	return append(key, newkey...), err
}

// Extending the localized privacy key according to Blumenthal key extension algorithm:
// https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#page-7
// Not many vendors use this algorithm.
// Previously implemented in the net-snmp and pysnmp libraries.
// TODO: Not tested
func extendKeyBlumenthal(authProtocol AuthProtocol, password string, engineID []byte) ([]byte, error) {
	key, err := PasswordToKey(authProtocol, password, engineID)
	if err != nil {
		return nil, err
	}

	newkey := authProtocol.HashType().New()
	_, _ = newkey.Write(key)
	return append(key, newkey.Sum(nil)...), err
}

func PasswordToKey(proto AuthProtocol, password string, engineId []byte) ([]byte, error) {
	return passwordToKey(proto, []byte(password), engineId)
}

func passwordToKey(proto AuthProtocol, password, engineId []byte) ([]byte, error) {
	var h hash.Hash
	switch proto {
	case MD5:
		h = md5.New()
	case SHA:
		h = sha1.New()
	case SHA224:
		h = crypto.SHA224.New()
	case SHA256:
		h = crypto.SHA256.New()
	case SHA384:
		h = crypto.SHA384.New()
	case SHA512:
		h = crypto.SHA512.New()
	default:
		return nil, fmt.Errorf("unknow auth protocol: %d", proto)
	}

	plen := len(password)
	for i := mega / plen; i > 0; i-- {
		h.Write(password)
	}
	remain := mega % plen
	if remain > 0 {
		h.Write(password[:remain])
	}
	ku := h.Sum(nil)

	// fmt.Println(ToHexStr(ku, ""))
	// bs, e := generate_keys(crypto.MD5, password)
	// fmt.Println(ToHexStr(bs, ""), e)

	h.Reset()
	h.Write(ku)
	h.Write(engineId)
	h.Write(ku)
	return h.Sum(nil), nil

	//return generate_localization_keys(crypto.MD5, ku, engineId)

	// fmt.Println("lock", ToHexStr(bs, ""), e)
	// fmt.Println(ToHexStr(a, ""), e)
	//return bs
}

// const (
// 	SNMP_AUTH_KEY_LOOPCNT     = 1048576
// 	SNMP_EXTENDED_KEY_SIZ int = 64
// )

// func generate_keys(hash crypto.Hash, passphrase string) ([]byte, error) {
// 	bytes := []byte(passphrase)
// 	passphrase_len := len(bytes)
// 	if 0 == passphrase_len {
// 		return nil, errors.New("passphrase is empty.")
// 	}

// 	var buf [SNMP_EXTENDED_KEY_SIZ]byte

// 	calc := hash.New()

// 	for loop := 0; loop < SNMP_AUTH_KEY_LOOPCNT; loop += SNMP_EXTENDED_KEY_SIZ {
// 		for i := 0; i < SNMP_EXTENDED_KEY_SIZ; i++ {
// 			buf[i] = bytes[(loop+i)%passphrase_len]
// 		}
// 		_, err := calc.Write(buf[:])
// 		if nil != err {
// 			return nil, err
// 		}
// 	}

// 	return calc.Sum(nil), nil
// }

// func generate_localization_keys(hash crypto.Hash, b1, b2 []byte) ([]byte, error) {
// 	calc := hash.New()
// 	_, err := calc.Write(b1)
// 	if nil != err {
// 		return nil, err
// 	}
// 	_, err = calc.Write(b2)
// 	if nil != err {
// 		return nil, err
// 	}
// 	_, err = calc.Write(b1)
// 	if nil != err {
// 		return nil, err
// 	}
// 	return calc.Sum(nil), nil
// }
