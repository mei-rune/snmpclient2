package snmpclient2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"

	"github.com/runner-mei/snmpclient2/asn1"
)

type Security interface {
	GenerateRequestMessage(*Arguments, Message) error
	ProcessIncomingMessage(*Arguments, Message) error
	Discover(*Arguments) error
	String() string
}

type community struct{}

func (c *community) GenerateRequestMessage(args *Arguments, sendMsg Message) error {
	m := sendMsg.(*MessageV1)
	m.Community = []byte(args.Community)

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

func (c *community) Discover(args *Arguments) error {
	return nil
}

func (c *community) String() string {
	return "{}"
}

type discoveryStatus int

const (
	noDiscovered discoveryStatus = iota
	noSynchronized
	discovered
)

func (d discoveryStatus) String() string {
	switch d {
	case noDiscovered:
		return "noDiscovered"
	case noSynchronized:
		return "noSynchronized"
	case discovered:
		return "discovered"
	default:
		return "Unknown"
	}
}

type USM struct {
	DiscoveryStatus discoveryStatus
	AuthEngineId    []byte
	AuthEngineBoots int64
	AuthEngineTime  int64
	AuthKey         []byte
	PrivKey         []byte
	UpdatedTime     time.Time
}

func (u *USM) GenerateRequestMessage(args *Arguments, sendMsg Message) (err error) {
	// setup message
	m := sendMsg.(*MessageV3)

	if u.DiscoveryStatus > noDiscovered {
		m.UserName = []byte(args.UserName)
		m.AuthEngineId = u.AuthEngineId
	}
	if u.DiscoveryStatus > noSynchronized {
		err = u.UpdateEngineBootsTime()
		if err != nil {
			return
		}
		m.AuthEngineBoots = u.AuthEngineBoots
		m.AuthEngineTime = u.AuthEngineTime
	}

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
			err = encrypt(m, args.PrivProtocol, u.PrivKey)
			if err != nil {
				return
			}
		}

		// get digest of whole message
		digest, e := mac(m, args.AuthProtocol, u.AuthKey)
		if e != nil {
			return e
		}
		m.AuthParameter = digest
	}

	return
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
		// get & check digest of whole message
		// digest, e := mac(rm, args.AuthProtocol, u.AuthKey)
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
			e := decrypt(rm, args.PrivProtocol, u.PrivKey, rm.PrivParameter)
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

func (u *USM) Discover(args *Arguments) (err error) {
	if args.SecurityEngineId != "" {
		securityEngineId, _ := engineIdToBytes(args.SecurityEngineId)
		u.SetAuthEngineId(args, securityEngineId)
		u.DiscoveryStatus = noSynchronized
		return
	}

	if u.DiscoveryStatus == noDiscovered {
		// Send an empty PDU with the NoAuthNoPriv
		orgSecLevel := args.SecurityLevel
		args.SecurityLevel = NoAuthNoPriv

		//pdu := NewPdu(args.Version, GetRequest)
		//_, err = snmp.sendPdu(pdu)

		args.SecurityLevel = orgSecLevel
		if err != nil {
			return
		}
	}

	if u.DiscoveryStatus == noSynchronized && args.SecurityLevel > NoAuthNoPriv {
		// Send an empty PDU
		//pdu := NewPdu(args.Version, GetRequest)
		//_, err = snmp.sendPdu(pdu)
		if err != nil {
			return
		}
	}

	return
}

func (u *USM) SetAuthEngineId(args *Arguments, authEngineId []byte) {
	u.AuthEngineId = authEngineId
	if len(args.AuthPassword) > 0 {
		u.AuthKey = PasswordToKey(args.AuthProtocol, args.AuthPassword, authEngineId)
	}
	if len(args.PrivPassword) > 0 {
		u.PrivKey = PasswordToKey(args.AuthProtocol, args.PrivPassword, authEngineId)
	}
}

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
		`{"DiscoveryStatus": "%s", "AuthEngineId": "%s", "AuthEngineBoots": "%d", `+
			`"AuthEngineTime": "%d", "AuthKey": "%s", "PrivKey": "%s", "UpdatedTime": "%s"}`,
		u.DiscoveryStatus, ToHexStr(u.AuthEngineId, ""), u.AuthEngineBoots, u.AuthEngineTime,
		ToHexStr(u.AuthKey, ""), ToHexStr(u.PrivKey, ""), u.UpdatedTime)
}

func mac(msg *MessageV3, proto AuthProtocol, key []byte) ([]byte, error) {
	tmp := msg.AuthParameter
	msg.AuthParameter = padding([]byte{}, 12)
	msgBytes, err := msg.Marshal()
	msg.AuthParameter = tmp
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch proto {
	case Md5:
		h = hmac.New(md5.New, key)
	case Sha:
		h = hmac.New(sha1.New, key)
	default:
		return nil, errors.New("'" + fmt.Sprint(proto) + "' is unsupported hash.")
	}
	h.Write(msgBytes)
	return h.Sum(nil)[:12], nil
}

func encrypt(msg *MessageV3, proto PrivProtocol, key []byte) (err error) {
	var dst, priv []byte
	src := msg.PduBytes()

	switch proto {
	case Des:
		dst, priv, err = EncryptDES(src, key, int32(msg.AuthEngineBoots), genSalt32())
	case Aes:
		dst, priv, err = EncryptAES(
			src, key, int32(msg.AuthEngineBoots), int32(msg.AuthEngineTime), genSalt64())
	default:
		err = errors.New("'" + fmt.Sprint(proto) + "' is unsupported crypto.")
	}
	if err != nil {
		return
	}

	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_OCTETSTRING, IsCompound: false}
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
	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_OCTETSTRING || raw.IsCompound {
		return asn1.StructuralError{fmt.Sprintf(
			"Invalid encrypted PDU object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(msg.PduBytes(), " "))}
	}

	var dst []byte
	switch proto {
	case Des:
		dst, err = DecryptDES(raw.Bytes, key, privParam)
	case Aes:
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

	block, err := aes.NewCipher(key[:16])
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

	block, err := aes.NewCipher(key[:16])
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

func PasswordToKey(proto AuthProtocol, password string, engineId []byte) []byte {
	var h hash.Hash
	switch proto {
	case Md5:
		h = md5.New()
	case Sha:
		h = sha1.New()
	}

	pass := []byte(password)
	plen := len(pass)
	for i := mega / plen; i > 0; i-- {
		h.Write(pass)
	}
	remain := mega % plen
	if remain > 0 {
		h.Write(pass[:remain])
	}
	ku := h.Sum(nil)

	h.Reset()
	h.Write(ku)
	h.Write(engineId)
	h.Write(ku)
	return h.Sum(nil)
}
