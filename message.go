package snmpclient2

import (
	"encoding/asn1"
	"fmt"
)

//  snmp messsage v1 or v2
// +----------------------------------+
// |  version  |  community   |  pdu  |
// +----------------------------------+
//
//
//                                                                                       |<------------ ScopedPdu ---------->|
//                  +--------------------------------------------------------------------------------------------------------+
// snmpv3 message   | version  | RequestID |  MaxSize |  Flag  | security   | Security   | context  | context |    PDU       |
//                  |          |           |          |        |   Model    | parameters | engineId |  name   |              |
//                  +--------------------------------------------------------------------------------------------------------+
//
//                                                                                       +-----------------------------------+
// ScopedPdu                                                                             | context  | context |    PDU       |
//                                                                                       | engineId |  name   |              |
//                                                                                       +-----------------------------------+
//
type Message interface {
	Version() SnmpVersion
	PDU() PDU
	PduBytes() []byte
	SetPduBytes([]byte)
	Marshal() ([]byte, error)
	Unmarshal([]byte) ([]byte, error)
	String() string
}

type MessageV1 struct {
	version   SnmpVersion
	Community []byte
	pduBytes  []byte
	pdu       PDU
}

func (msg *MessageV1) Version() SnmpVersion {
	return msg.version
}

func (msg *MessageV1) PDU() PDU {
	return msg.pdu
}

func (msg *MessageV1) PduBytes() []byte {
	return msg.pduBytes
}

func (msg *MessageV1) SetPduBytes(b []byte) {
	msg.pduBytes = b
}

func (msg *MessageV1) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_SEQUENCE, IsCompound: true}

	buf, err = asn1.Marshal(msg.version)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(msg.Community)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	raw.Bytes = append(raw.Bytes, msg.pduBytes...)
	return asn1.Marshal(raw)
}

func (msg *MessageV1) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}
	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid MessageV1 object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	next := raw.Bytes

	var version int
	next, err = asn1.Unmarshal(next, &version)
	if err != nil {
		return
	}

	var community []byte
	next, err = asn1.Unmarshal(next, &community)
	if err != nil {
		return
	}

	msg.version = SnmpVersion(version)
	msg.Community = community
	msg.pduBytes = next
	return
}

func (msg *MessageV1) String() string {
	var pduStr string
	if nil != msg.pdu {
		pduStr = msg.pdu.String()
	}
	return fmt.Sprintf(
		`{"Version": "%s", "Community": "%s", "PDU": %s}`,
		msg.version, msg.Community, pduStr)
}

type securityModel int

const (
	securityUsm = 3
)

func (s securityModel) String() string {
	switch s {
	case securityUsm:
		return "USM"
	default:
		return "Unknown"
	}
}

type globalDataV3 struct {
	MessageId      int
	MessageMaxSize int
	MessageFlags   []byte
	SecurityModel  securityModel
}

func (h *globalDataV3) Marshal() (b []byte, err error) {
	return asn1.Marshal(*h)
}

func (h *globalDataV3) Unmarshal(b []byte) (rest []byte, err error) {
	return asn1.Unmarshal(b, h)
}

func (h *globalDataV3) initFlags() {
	if len(h.MessageFlags) == 0 {
		h.MessageFlags = append(h.MessageFlags, 0)
	}
}

func (h *globalDataV3) SetReportable(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x04
	} else {
		h.MessageFlags[0] &= 0xfb
	}
}

func (h *globalDataV3) Reportable() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x04 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) SetPrivacy(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x02
	} else {
		h.MessageFlags[0] &= 0xfd
	}
}

func (h *globalDataV3) Privacy() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x02 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) SetAuthentication(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x01
	} else {
		h.MessageFlags[0] &= 0xfe
	}
}

func (h *globalDataV3) Authentication() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x01 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) String() string {
	var flags string
	if h.Authentication() {
		flags += "a"
	}
	if h.Privacy() {
		flags += "p"
	}
	if h.Reportable() {
		flags += "r"
	}

	return fmt.Sprintf(
		`{"MessageId": "%d", "MessageMaxSize": "%d", "MessageFlags": "%s", `+
			`"SecurityModel": "%s"}`,
		h.MessageId, h.MessageMaxSize, flags, h.SecurityModel)
}

type securityParameterV3 struct {
	AuthEngineId    []byte
	AuthEngineBoots int64
	AuthEngineTime  int64
	UserName        []byte
	// If the packet has been authenticated, then this field contains the computed HMAC-MD5 or HMAC-SHA message digest for the packet.
	// 如果包是认证过的, 那么这个字段包含计算好的该包的 HMAC-MD5 或 HMAC-SHA 消息摘要.
	AuthParameter []byte
	// If the scopedPDU of the packet has been encrypted, then this field contains the salt (i.e. random variant) that was used as input to the DES algorithm.
	// 如果包的 scopedPDU 是被加密过的, 那么这个字段包含用于DES算法输入的 salt (例如 随机变量).
	PrivParameter []byte
}

func (sec *securityParameterV3) Marshal() ([]byte, error) {
	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_OCTETSTRING, IsCompound: false}

	buf, err := asn1.Marshal(*sec)
	if err != nil {
		return nil, err
	}
	raw.Bytes = buf

	return asn1.Marshal(raw)
}

func (sec *securityParameterV3) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}

	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_OCTETSTRING || raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid SecurityParameter object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	_, err = asn1.Unmarshal(raw.Bytes, sec)
	return
}

func (sec *securityParameterV3) String() string {
	return fmt.Sprintf(
		`{"AuthEngineId": "%s", "AuthEngineBoots": "%d", "AuthEngineTime": "%d", `+
			`"UserName": "%s", "AuthParameter": "%s", "PrivParameter": "%s"}`,
		ToHexStr(sec.AuthEngineId, ""), sec.AuthEngineBoots, sec.AuthEngineTime, sec.UserName,
		ToHexStr(sec.AuthParameter, ":"), ToHexStr(sec.PrivParameter, ":"))
}

//
//                                                                                       |<------------ ScopedPdu ---------->|
//                  +--------------------------------------------------------------------------------------------------------+
// snmpv3 message   | version  | RequestID |  MaxSize |  Flag  | security   | Security   | context  | context |    PDU       |
//                  |          |           |          |        |   Model    | parameters | engineId |  name   |              |
//                  +--------------------------------------------------------------------------------------------------------+
//
//                                                                                       +-----------------------------------+
// ScopedPdu                                                                             | context  | context |    PDU       |
//                                                                                       | engineId |  name   |              |
//                                                                                       +-----------------------------------+
//
//
//
//                     SNMPv3 Packet Format
//
//                   -------------------------
//     /|\           | msgVersion            |
//      |            |-----------------------|
//      |            | msgID                 |
//      |            |-----------------------|         USM Security Parameters
//      |            | msgMaxSize            |
//      |            |-----------------------|    /-------------------------------
//      |            | msgFlags              |   / | msgAuthoritativeEngineID    |
//   scope of        |-----------------------|  /  |-----------------------------|
// authentication    | msgSecurityModel      | /   | msgAuthoritativeEngineBoots |
//      |            |-----------------------|/    |-----------------------------|
//      |            |                       |     | msgAuthoritativeEngineTime  |
//      |            | msgSecurityParameters |     |-----------------------------|
//      |            |                       |     | msgUserName                 |
//      |            |-----------------------|\    |-----------------------------|
//      |     /|\    |                       | \   | msgAuthenticationParameters |
//      |      |     |                       |  \  |-----------------------------|
//      |      |     |                       |   \ | msgPrivacyParameters        |
//      |  scope of  | scopedPDU             |    \-------------------------------
//      | encryption |                       |
//      |      |     |                       |
//      |      |     |                       |
//      |      |     |                       |
//     \|/    \|/    |                       |
//                   -------------------------
//
type MessageV3 struct {
	globalDataV3
	securityParameterV3
	MessageV1
}

func (msg *MessageV3) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_SEQUENCE, IsCompound: true}

	buf, err = asn1.Marshal(msg.version)
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = msg.globalDataV3.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = msg.securityParameterV3.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	raw.Bytes = append(raw.Bytes, msg.pduBytes...)
	return asn1.Marshal(raw)
}

func (msg *MessageV3) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid MessageV3 object - Class [%02x], Tag [%02x] : [%s]",
			raw.FullBytes[0], SYNTAX_SEQUENCE, ToHexStr(b, " "))}
	}

	next := raw.Bytes

	var version int
	next, err = asn1.Unmarshal(next, &version)
	if err != nil {
		return
	}

	next, err = msg.globalDataV3.Unmarshal(next)
	if err != nil {
		return
	}

	next, err = msg.securityParameterV3.Unmarshal(next)
	if err != nil {
		return
	}

	msg.version = SnmpVersion(version)
	msg.pduBytes = next
	return
}

func (msg *MessageV3) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "GlobalData": %s, "SecurityParameter": %s, "PDU": %s}`,
		msg.version, msg.globalDataV3.String(), msg.securityParameterV3.String(),
		msg.pdu.String())
}

func NewMessage(ver SnmpVersion, pdu PDU) (msg Message) {
	m := MessageV1{
		version: ver,
		pdu:     pdu,
	}
	switch ver {
	case V1, V2c:
		msg = &m
	case V3:
		msg = &MessageV3{
			MessageV1:    m,
			globalDataV3: globalDataV3{MessageFlags: []byte{0}},
		}
	}
	return
}

type MessageProcessing interface {
	Security() Security
	PrepareOutgoingMessage(*SNMP, PDU) (Message, error)
	PrepareDataElements(*SNMP, Message, []byte) (PDU, error)
}

type messageProcessingV1 struct {
	security Security
}

func (mp *messageProcessingV1) Security() Security {
	return mp.security
}

func (mp *messageProcessingV1) PrepareOutgoingMessage(
	snmp *SNMP, pdu PDU) (msg Message, err error) {

	pdu.SetRequestId(genRequestId())
	msg = NewMessage(snmp.args.Version, pdu)

	err = mp.security.GenerateRequestMessage(&snmp.args, msg)
	return
}

func (mp *messageProcessingV1) PrepareDataElements(
	snmp *SNMP, sendMsg Message, b []byte) (pdu PDU, err error) {

	pdu = &PduV1{}
	recvMsg := NewMessage(snmp.args.Version, pdu)
	_, err = recvMsg.Unmarshal(b)
	if err != nil {
		return nil, ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal message",
			Detail:  fmt.Sprintf("message Bytes - [%s]", ToHexStr(b, " ")),
		}
	}

	if sendMsg.Version() != recvMsg.Version() {
		return nil, ResponseError{
			Message: fmt.Sprintf(
				"SnmpVersion mismatch - expected [%v], actual [%v]",
				sendMsg.Version(), recvMsg.Version()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}

	err = mp.security.ProcessIncomingMessage(&snmp.args, recvMsg)
	if err != nil {
		return nil, err
	}

	if recvMsg.PDU().PduType() != GetResponse {
		return nil, ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]",
				GetResponse, recvMsg.PDU().PduType()),
		}
	}
	if sendMsg.PDU().RequestId() != recvMsg.PDU().RequestId() {
		return nil, ResponseError{
			Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
				sendMsg.PDU().RequestId(), recvMsg.PDU().RequestId()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}
	return
}

type messageProcessingV3 struct {
	security Security
}

func (mp *messageProcessingV3) Security() Security {
	return mp.security
}

func (mp *messageProcessingV3) PrepareOutgoingMessage(
	snmp *SNMP, pdu PDU) (msg Message, err error) {

	pdu.SetRequestId(genRequestId())
	msg = NewMessage(snmp.args.Version, pdu)

	m := msg.(*MessageV3)
	m.MessageId = genMessageId()
	m.MessageMaxSize = snmp.args.MessageMaxSize
	m.SecurityModel = securityUsm
	m.SetReportable(confirmedType(pdu.PduType()))
	if snmp.args.SecurityLevel >= AuthNoPriv {
		m.SetAuthentication(true)
		if snmp.args.SecurityLevel >= AuthPriv {
			m.SetPrivacy(true)
		}
	}

	err = mp.security.GenerateRequestMessage(&snmp.args, msg)
	return
}

func (mp *messageProcessingV3) PrepareDataElements(
	snmp *SNMP, sendMsg Message, b []byte) (pdu PDU, err error) {

	pdu = &ScopedPdu{}
	recvMsg := NewMessage(snmp.args.Version, pdu)
	_, err = recvMsg.Unmarshal(b)
	if err != nil {
		return nil, ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal message",
			Detail:  fmt.Sprintf("message Bytes - [%s]", ToHexStr(b, " ")),
		}
	}

	sm := sendMsg.(*MessageV3)
	rm := recvMsg.(*MessageV3)
	if sm.Version() != rm.Version() {
		return nil, ResponseError{
			Message: fmt.Sprintf(
				"SnmpVersion mismatch - expected [%v], actual [%v]", sm.Version(), rm.Version()),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}
	if sm.MessageId != rm.MessageId {
		return nil, ResponseError{
			Message: fmt.Sprintf(
				"MessageId mismatch - expected [%d], actual [%d]", sm.MessageId, rm.MessageId),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}
	if rm.SecurityModel != securityUsm {
		return nil, ResponseError{
			Message: fmt.Sprintf("Unknown SecurityModel, value [%d]", rm.SecurityModel),
		}
	}

	err = mp.security.ProcessIncomingMessage(&snmp.args, recvMsg)
	if err != nil {
		return nil, err
	}

	switch t := rm.PDU().PduType(); t {
	case GetResponse:
		if sm.PDU().RequestId() != rm.PDU().RequestId() {
			return nil, ResponseError{
				Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
					sm.PDU().RequestId(), rm.PDU().RequestId()),
				Detail: fmt.Sprintf("%s vs %s", sm, rm),
			}
		}
	case Report:
		if sm.Reportable() {
			break
		}
		fallthrough
	default:
		return nil, ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]", GetResponse, t),
		}
	}

	return
}

func NewMessageProcessing(ver SnmpVersion) (mp MessageProcessing) {
	switch ver {
	case V1, V2c:
		mp = &messageProcessingV1{security: &community{}}
	case V3:
		mp = &messageProcessingV3{security: &USM{}}
	}
	return
}
