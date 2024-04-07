package snmpclient2_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/runner-mei/snmpclient2"
)

func TestMessageV1(t *testing.T) {
	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetRequest)
	msg := snmpclient2.NewMessage(snmpclient2.V2c, pdu).(*snmpclient2.MessageV1)
	b, _ := pdu.Marshal()
	msg.SetPduBytes(b)
	msg.Community = []byte("MyCommunity")

	expBuf := []byte{
		0x30, 0x1d, 0x02, 0x01, 0x01, 0x04, 0x0b, 0x4d, 0x79, 0x43, 0x6f,
		0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x74, 0x79, 0xa0, 0x0b, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}
	buf, err := msg.Marshal()
	if err != nil {
		t.Fatal("Marshal() : ", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	expStr := `{"Version": "2c", "Community": "MyCommunity", ` +
		`"PDU": {"Type": "GetRequest", "RequestId": "0", "ErrorStatus": ` +
		`"NoError", "ErrorIndex": "0", "VariableBindings": []}}`
	m := snmpclient2.NewMessage(snmpclient2.V2c, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

func TestMessageV3(t *testing.T) {
	pdu := snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetRequest)
	msg := snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	b, _ := pdu.Marshal()
	msg.SetPduBytes(b)
	msg.MessageId = 123
	msg.MessageMaxSize = 321
	msg.SetReportable(true)
	msg.SetPrivacy(true)
	msg.SetAuthentication(true)
	msg.SecurityModel = 3
	msg.AuthEngineId = []byte{0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	msg.AuthEngineBoots = 456
	msg.AuthEngineTime = 654
	msg.UserName = []byte("User")
	msg.AuthParameter = []byte{0xaa, 0xbb, 0xcc}
	msg.PrivParameter = []byte{0xdd, 0xee, 0xff}

	expBuf := []byte{
		0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x02, 0x01, 0x7b,
		0x02, 0x02, 0x01, 0x41, 0x04, 0x01, 0x07, 0x02, 0x01, 0x03,
		0x04, 0x24, 0x30, 0x22, 0x04, 0x08, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x02, 0x02, 0x01, 0xc8, 0x02, 0x02, 0x02, 0x8e, 0x04, 0x04, 0x55, 0x73, 0x65, 0x72,
		0x04, 0x03, 0xaa, 0xbb, 0xcc, 0x04, 0x03, 0xdd, 0xee, 0xff,
		0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}

	buf, err := msg.Marshal()
	if err != nil {
		t.Fatal("Marshal() : ", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	expStr := `{"Version": "3", "GlobalData": {"MessageId": "123", "MessageMaxSize": "321", ` +
		`"MessageFlags": "apr", "SecurityModel": "USM"}, "SecurityParameter": ` +
		`{"AuthEngineId": "8001020304050607", "AuthEngineBoots": "456", ` +
		`"AuthEngineTime": "654", "UserName": "User", "AuthParameter": "aa:bb:cc", ` +
		`"PrivParameter": "dd:ee:ff"}, "PDU": {"Type": "GetRequest", "RequestId": "0", ` +
		`"ErrorStatus": "NoError", "ErrorIndex": "0", "ContextEngineId": "", ` +
		`"ContextName": "", "VariableBindings": []}}`
	m := snmpclient2.NewMessage(snmpclient2.V3, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

func TestMessageProcessingV1(t *testing.T) {
	snmp, _ := snmpclient2.NewSNMP("udp", "127.0.0.1", snmpclient2.Arguments{
		Version:   snmpclient2.V2c,
		Community: "public",
	})
	mp := snmpclient2.NewMessageProcessing(snmpclient2.V2c)
	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetRequest)

	msg, err := mp.PrepareOutgoingMessage(snmp, pdu)
	if err != nil {
		t.Errorf("PrepareOutgoingMessage() - has error %v", err)
	}
	if len(msg.PduBytes()) == 0 {
		t.Error("PrepareOutgoingMessage() - pdu bytes")
	}
	if pdu.RequestId() == 0 {
		t.Error("PrepareOutgoingMessage() - request id")
	}
	requestId := pdu.RequestId()

	_, err = mp.PrepareDataElements(snmp, msg, []byte{0x00, 0x00})
	if err == nil {
		t.Error("PrepareDataElements() - message unmarshal error")
	}

	b, _ := msg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - pdu type check")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetResponse)
	rmsg := snmpclient2.NewMessage(snmpclient2.V2c, pdu).(*snmpclient2.MessageV1)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - version check")
	}

	pdu.SetRequestId(requestId)
	pduBytes, _ := pdu.Marshal()
	rmsg = snmpclient2.NewMessage(snmpclient2.V2c, pdu).(*snmpclient2.MessageV1)
	rmsg.Community = []byte("public")
	rmsg.SetPduBytes(pduBytes)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err != nil {
		t.Errorf("PrepareDataElements() - has error %v", err)
	}
}

func TestMessageProcessingV3(t *testing.T) {
	snmp, _ := snmpclient2.NewSNMP("udp", "127.0.0.1", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "myName",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpclient2.MD5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpclient2.DES,
	})
	var mss snmpclient2.Message = &snmpclient2.MessageV1{}
	t.Log(mss.String())
	mp := snmpclient2.NewMessageProcessing(snmpclient2.V3)
	//usm := mp.Security().(*snmpclient2.USM)
	//usm.AuthKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	//usm.PrivKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pdu := snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetRequest)

	msg, err := mp.PrepareOutgoingMessage(snmp, pdu)
	if err != nil {
		t.Errorf("PrepareOutgoingMessage() - has error %v", err)
	}
	if len(msg.PduBytes()) == 0 {
		t.Error("PrepareOutgoingMessage() - pdu bytes")
	}
	if pdu.RequestId() == 0 {
		t.Error("PrepareOutgoingMessage() - request id")
	}
	msgv3 := msg.(*snmpclient2.MessageV3)
	if msgv3.MessageId == 0 {
		t.Error("PrepareOutgoingMessage() - message id")
	}
	if !msgv3.Reportable() || !msgv3.Authentication() || !msgv3.Privacy() {
		t.Error("PrepareOutgoingMessage() - security flag")
	}
	msgv3.SetAuthentication(false)
	msgv3.SetPrivacy(false)
	msgv3.AuthEngineId = []byte{0, 0, 0, 0, 0}
	requestId := pdu.RequestId()
	messageId := msgv3.MessageId

	_, err = mp.PrepareDataElements(snmp, msg, []byte{0x00, 0x00})
	if err == nil {
		t.Error("PrepareDataElements() - message unmarshal error")
	}

	b, _ := msg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - pdu type check")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetResponse)
	rmsg := snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - message id check")
	}

	rmsg = snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	rmsg.AuthEngineId = []byte{0, 0, 0, 0, 0}
	rmsg.MessageId = messageId
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - security model check")
	}

	pdu.(*snmpclient2.ScopedPdu).ContextEngineId = rmsg.AuthEngineId
	pduBytes, _ := pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	rmsg.SecurityModel = 3
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - request id check")
	}

	pdu.SetRequestId(requestId)
	pduBytes, _ = pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	rmsg.UserName = []byte(snmpclient2.GetArgs(snmp).UserName)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err != nil {
		t.Errorf("PrepareDataElements() - has error %v", err)
	}
}

// Failed to process incoming message - Failed to Unmarshal PDU, cause `asn1: syntax error: zero length OBJECT IDENTIFIER`
func TestMessageV1Unmarshal1(t *testing.T) {
	buf := []byte{0x30, 0x82, 0x00, 0x89, 0x02, 0x01, 0x01, 0x04, 0x0a, 0x64, 0x7a, 0x67, 0x77,
		0x40, 0x6a, 0x78, 0x7a, 0x7a, 0x62, 0xa2, 0x78, 0x02, 0x03, 0x01, 0xaf, 0xa2, 0x02,
		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x6b, 0x30, 0x1c, 0x06, 0x0f, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x02, 0xa0, 0x87, 0x80, 0x0c, 0x04, 0x09,
		0x43, 0x61, 0x72, 0x64, 0x20, 0x73, 0x6c, 0x6f, 0x74, 0x30, 0x13, 0x06, 0x0f, 0x2b,
		0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x03, 0xa0, 0x87, 0x80, 0x0c,
		0x06, 0x00, 0x30, 0x14, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01,
		0x01, 0x01, 0x05, 0xa0, 0x87, 0x80, 0x0c, 0x02, 0x01, 0x05, 0x30, 0x20, 0x06, 0x0f,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x07, 0xa0, 0x87, 0x80,
		0x0c, 0x04, 0x0d, 0x43, 0x61, 0x72, 0x64, 0x20, 0x73, 0x6c, 0x6f, 0x74, 0x20, 0x30,
		0x2f, 0x37}

	expStr := `{"Version": "2c", "Community": "dzgw@jxzzb", "PDU": {"Type": "GetResponse", "RequestId": "110498", ` +
		`"ErrorStatus": "NoError", "ErrorIndex": "0", "VariableBindings": [{"Oid": "1.3.6.1.2.1.47.1.1.1.1.2.67223564", ` +
		`"Variable": {"Type": "octets", "Value": "4361726420736c6f74"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.3.67223564", ` +
		`"Variable": {"Type": "oid", "Value": ""}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.5.67223564", "Variable": {"Type": "int", ` +
		`"Value": "5"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.7.67223564", "Variable": {"Type": "octets", "Value": ` +
		`"4361726420736c6f7420302f37"}}]}}`

	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetResponse)
	m := snmpclient2.NewMessage(snmpclient2.V2c, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}

	mp := snmpclient2.NewCommunity()

	if err = mp.ProcessIncomingMessage(nil, m); nil != err {
		t.Error(err)
		return
	}
	//pdu.Unmarshal()

	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

// Failed to process incoming message - Failed to Unmarshal PDU, cause `asn1: structure error: integer not minimally-encoded`
func TestMessageV1Unmarshal2(t *testing.T) {
	buf := []byte{0x30, 0x7e, 0x02, 0x01, 0x01, 0x04, 0x0a, 0x64, 0x7a, 0x67, 0x77, 0x40,
		0x6a, 0x78, 0x7a, 0x7a, 0x62, 0xa2, 0x6d, 0x02, 0x03, 0x02, 0x14, 0x9e, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x30, 0x60, 0x30, 0x11, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x06, 0x01, 0x00, 0x30, 0x11, 0x06,
		0x0c, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x04, 0x01, 0x02,
		0x01, 0x00, 0x30, 0x14, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01,
		0x01, 0x01, 0x06, 0x01, 0x02, 0x04, 0xff, 0xff, 0xff, 0xff, 0x30, 0x10, 0x06, 0x0c,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x08, 0x01, 0x04, 0x00,
		0x30, 0x10, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01,
		0x0e, 0x01, 0x04, 0x00}

	expStr := `{"Version": "2c", "Community": "dzgw@jxzzb", "PDU": {"Type": "GetResponse", "RequestId": "136350",` +
		` "ErrorStatus": "NoError", "ErrorIndex": "0", "VariableBindings": [{"Oid": "1.3.6.1.2.1.47.1.1.1.1.3.1",` +
		` "Variable": {"Type": "oid", "Value": "0.0"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.4.1", "Variable": {"Type": "int",` +
		` "Value": "0"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.6.1", "Variable": {"Type": "int", "Value": "-1"}}, {"Oid":` +
		` "1.3.6.1.2.1.47.1.1.1.1.8.1", "Variable": {"Type": "octets", "Value": ""}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.14.1",` +
		` "Variable": {"Type": "octets", "Value": ""}}]}}`

	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetResponse)
	m := snmpclient2.NewMessage(snmpclient2.V2c, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}

	mp := snmpclient2.NewCommunity()

	if err = mp.ProcessIncomingMessage(nil, m); nil != err {
		t.Error(err)
		return
	}
	//pdu.Unmarshal()

	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

func TestMessageV1Unmarshal3(t *testing.T) {
	txt := "30819f020101040863735f64626f6e65a2818f020301298d0201000201003081813010060b2b060102011902030101220201223018060b2b0601020119020301022206092b06010201190201043014060b2b0601020119020301032204052f646174613011060b2b06010201190203010422020210003014060b2b06010201190203010522020500acce08003014060b2b06010201190203010622020500986aad9b"

	buf, _ := hex.DecodeString(txt)
	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetResponse)
	m := snmpclient2.NewMessage(snmpclient2.V2c, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}

	mp := snmpclient2.NewCommunity()

	if err = mp.ProcessIncomingMessage(nil, m); nil != err {
		t.Error(err)
		return
	}
	// //pdu.Unmarshal()
	// expStr := `{"Version": "2c", "Community": "dzgw@jxzzb", "PDU": {"Type": "GetResponse", "RequestId": "136350",` +
	// 	` "ErrorStatus": "NoError", "ErrorIndex": "0", "VariableBindings": [{"Oid": "1.3.6.1.2.1.47.1.1.1.1.3.1",` +
	// 	` "Variable": {"Type": "oid", "Value": "0.0"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.4.1", "Variable": {"Type": "int",` +
	// 	` "Value": "0"}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.6.1", "Variable": {"Type": "int", "Value": "-1"}}, {"Oid":` +
	// 	` "1.3.6.1.2.1.47.1.1.1.1.8.1", "Variable": {"Type": "octets", "Value": ""}}, {"Oid": "1.3.6.1.2.1.47.1.1.1.1.14.1",` +
	// 	` "Variable": {"Type": "octets", "Value": ""}}]}}`

	// if expStr != m.String() {
	// 	t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	// }
}
