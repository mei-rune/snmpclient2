package snmpclient2

import (
	"encoding/asn1"
	"fmt"
)

//  snmp messsage v1 or v2
// +----------------------------------+
// |  version  |  community   |  pdu  |
// +----------------------------------+

//  snmp messsage v3
// +--------------------------------------------------------------------------------------------------------------------------------+
// |  version  |  request_id   |  max_size  |  flags  |  security_model  |  security_params  |  context_engine_id  |  context_name  |
// +--------------------------------------------------------------------------------------------------------------------------------+

type Message interface {
	Version() SNMPVersion
	Pdu() Pdu
	PduBytes() []byte
	SetPduBytes([]byte)
	Marshal() ([]byte, error)
	Unmarshal([]byte) ([]byte, error)
	String() string
}

type MessageV1 struct {
	version   SNMPVersion
	Community []byte
	pduBytes  []byte
	pdu       Pdu
}

func (msg *MessageV1) Version() SNMPVersion {
	return msg.version
}

func (msg *MessageV1) Pdu() Pdu {
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
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

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
	if raw.Class != classUniversal || raw.Tag != tagSequence || !raw.IsCompound {
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

	msg.version = SNMPVersion(version)
	msg.Community = community
	msg.pduBytes = next
	return
}

func (msg *MessageV1) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "Community": "%s", "Pdu": %s}`,
		msg.version, msg.Community, msg.pdu.String())
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
	AuthParameter   []byte
	PrivParameter   []byte
}

func (sec *securityParameterV3) Marshal() ([]byte, error) {
	raw := asn1.RawValue{Class: classUniversal, Tag: tagOctetString, IsCompound: false}

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

	if raw.Class != classUniversal || raw.Tag != tagOctetString || raw.IsCompound {
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

// snmp messsage v3
// +--------------------------------------------------------------------------------------------------------------------------------+
// |  version  |  request_id   |  max_size  |  flags  |  security_model  |  security_params  |  context_engine_id  |  context_name  |
// +--------------------------------------------------------------------------------------------------------------------------------+
type MessageV3 struct {
	globalDataV3
	securityParameterV3
	MessageV1
}

func (msg *MessageV3) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

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
	if raw.Class != classUniversal || raw.Tag != tagSequence || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid MessageV3 object - Class [%02x], Tag [%02x] : [%s]",
			raw.FullBytes[0], tagSequence, ToHexStr(b, " "))}
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

	msg.version = SNMPVersion(version)
	msg.pduBytes = next
	return
}

func (msg *MessageV3) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "GlobalData": %s, "SecurityParameter": %s, "Pdu": %s}`,
		msg.version, msg.globalDataV3.String(), msg.securityParameterV3.String(),
		msg.pdu.String())
}

func NewMessage(ver SNMPVersion, pdu Pdu) (msg Message) {
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

type messageProcessing interface {
	Security() Security
	PrepareOutgoingMessage(*SNMP, Pdu) (Message, error)
	PrepareDataElements(*SNMP, Message, []byte) (Pdu, error)
}

type messageProcessingV1 struct {
	security Security
}

func (mp *messageProcessingV1) Security() Security {
	return mp.security
}

func (mp *messageProcessingV1) PrepareOutgoingMessage(
	snmp *SNMP, pdu Pdu) (msg Message, err error) {

	pdu.SetRequestId(genRequestId())
	msg = NewMessage(snmp.args.Version, pdu)

	err = mp.security.GenerateRequestMessage(snmp, msg)
	return
}

func (mp *messageProcessingV1) PrepareDataElements(
	snmp *SNMP, sendMsg Message, b []byte) (pdu Pdu, err error) {

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
				"SNMPVersion mismatch - expected [%v], actual [%v]",
				sendMsg.Version(), recvMsg.Version()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}

	err = mp.security.ProcessIncomingMessage(snmp, sendMsg, recvMsg)
	if err != nil {
		return nil, err
	}

	if recvMsg.Pdu().PduType() != GetResponse {
		return nil, ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]",
				GetResponse, recvMsg.Pdu().PduType()),
		}
	}
	if sendMsg.Pdu().RequestId() != recvMsg.Pdu().RequestId() {
		return nil, ResponseError{
			Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
				sendMsg.Pdu().RequestId(), recvMsg.Pdu().RequestId()),
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
	snmp *SNMP, pdu Pdu) (msg Message, err error) {

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

	err = mp.security.GenerateRequestMessage(snmp, msg)
	return
}

func (mp *messageProcessingV3) PrepareDataElements(
	snmp *SNMP, sendMsg Message, b []byte) (pdu Pdu, err error) {

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
				"SNMPVersion mismatch - expected [%v], actual [%v]", sm.Version(), rm.Version()),
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

	err = mp.security.ProcessIncomingMessage(snmp, sendMsg, recvMsg)
	if err != nil {
		return nil, err
	}

	switch t := rm.Pdu().PduType(); t {
	case GetResponse:
		if sm.Pdu().RequestId() != rm.Pdu().RequestId() {
			return nil, ResponseError{
				Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
					sm.Pdu().RequestId(), rm.Pdu().RequestId()),
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

func NewMessageProcessing(ver SNMPVersion) (mp messageProcessing) {
	switch ver {
	case V1, V2c:
		mp = &messageProcessingV1{security: &community{}}
	case V3:
		mp = &messageProcessingV3{security: &USM{}}
	}
	return
}
