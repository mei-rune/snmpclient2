package snmpclient2_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/runner-mei/snmpclient2"
)

// RFC3414 A.3
func TestPasswordToKey(t *testing.T) {
	password := "maplesyrup"
	engineId := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	expBuf := []byte{
		0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f,
		0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b,
	}
	key, err := snmpclient2.PasswordToKey(snmpclient2.MD5, password, engineId)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(expBuf, key) {
		t.Errorf("PasswordToKey(Md5) - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(key, " "))
	}

	expBuf = []byte{
		0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23,
		0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f,
	}
	key, err = snmpclient2.PasswordToKey(snmpclient2.SHA, password, engineId)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(expBuf, key) {
		t.Errorf("PasswordToKey(Aes) - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(key, " "))
	}
}

func TestCipher(t *testing.T) {
	original := []byte("my private message.")
	password := "maplesyrup"
	engineId := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	engineBoots := int32(100)
	engineTime := int32(1234567)

	key, err := snmpclient2.PasswordToKey(snmpclient2.SHA, password, engineId)
	if err != nil {
		t.Error(err)
		return
	}

	cipher, priv, err := snmpclient2.EncryptDES(original, key, engineBoots, 100)
	if err != nil {
		t.Errorf("DES Encrypt err %v", err)
		return
	}
	result, err := snmpclient2.DecryptDES(cipher, key, priv)
	if err != nil {
		t.Errorf("DES Decrypt err %v", err)
		return
	}
	if bytes.Equal(original, result) {
		t.Errorf("DES Encrypt, Decrypt - expected [%s], actual [%s]", original, result)
		return
	}

	cipher, priv, err = snmpclient2.EncryptAES(original, key, engineBoots, engineTime, 100)
	if err != nil {
		t.Errorf("AES Encrypt err %v", err)
		return
	}
	result, err = snmpclient2.DecryptAES(cipher, key, priv, engineBoots, engineTime)
	if err != nil {
		t.Errorf("AES Decrypt err %v", err)
		return
	}
	if bytes.Equal(original, result) {
		t.Errorf("AES Encrypt, Decrypt - expected [%s], actual [%s]", original, result)
		return
	}
}

func TestCommunity(t *testing.T) {
	expCom := "public"
	snmp, _ := snmpclient2.NewSNMP("udp", "127.0.0.1", snmpclient2.Arguments{
		Version:   snmpclient2.V2c,
		Community: expCom,
	})
	sec := snmpclient2.NewCommunity()
	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetRequest)
	smsg := snmpclient2.NewMessage(snmpclient2.V2c, pdu).(*snmpclient2.MessageV1)

	err := sec.GenerateRequestMessage(snmpclient2.GetArgs(snmp), smsg)
	if err != nil {
		t.Errorf("GenerateRequestMessage() - has error %v", err)
	}
	if !bytes.Equal(smsg.Community, []byte(expCom)) {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]", expCom, smsg.Community)
	}
	if len(smsg.PduBytes()) == 0 {
		t.Error("GenerateRequestMessage() - pdu marshal")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetResponse)
	rmsg := snmpclient2.NewMessage(snmpclient2.V2c, pdu).(*snmpclient2.MessageV1)

	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - community check")
	}

	rmsg.Community = []byte(expCom)
	rmsg.SetPduBytes(smsg.PduBytes())
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err != nil {
		t.Errorf("ProcessIncomingMessage() - has error %v", err)
	}
}

func aTestUsm(t *testing.T) {
	expUser := []byte("myUser")
	expEngId := []byte{0x80, 0x00, 0x00, 0x00, 0x01}
	expCtxId := []byte{0x80, 0x00, 0x00, 0x00, 0x05}
	expCtxName := "myName"
	snmp, _ := snmpclient2.NewSNMP("udp", "127.0.0.1",
		snmpclient2.Arguments{
			Version:         snmpclient2.V3,
			UserName:        string(expUser),
			SecurityLevel:   snmpclient2.AuthPriv,
			AuthPassword:    "aaaaaaaa",
			AuthProtocol:    snmpclient2.MD5,
			PrivPassword:    "bbbbbbbb",
			PrivProtocol:    snmpclient2.DES,
			ContextEngineId: hex.EncodeToString(expCtxId),
			ContextName:     expCtxName,
		})
	sec := snmpclient2.NewUsm().(*snmpclient2.USM)
	pdu := snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetRequest)
	spdu := pdu.(*snmpclient2.ScopedPdu)
	smsg := snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	smsg.SetAuthentication(false)
	smsg.SetPrivacy(false)

	// Discovery
	err := sec.GenerateRequestMessage(snmpclient2.GetArgs(snmp), smsg)
	if err != nil {
		t.Errorf("GenerateRequestMessage() - has error %v", err)
	}
	if !bytes.Equal(spdu.ContextEngineId, expCtxId) {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]",
			expCtxId, spdu.ContextEngineId)
	}
	if string(spdu.ContextName) != expCtxName {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]",
			expCtxName, string(spdu.ContextName))
	}
	if len(smsg.PduBytes()) == 0 {
		t.Error("GenerateRequestMessage() - pdu marshal")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.Report)
	rmsg := snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	rmsg.SetPduBytes(smsg.PduBytes())
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - engineId check")
	}

	rmsg.AuthEngineId = expEngId
	rmsg.AuthEngineBoots = -1
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - boots check")
	}

	rmsg.AuthEngineBoots = 1
	rmsg.AuthEngineTime = -1
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - time check")
	}

	rmsg.AuthEngineTime = 1
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err != nil {
		t.Errorf("ProcessIncomingMessage() - has error %v", err)
	}
	if !bytes.Equal(sec.AuthEngineId, expEngId) {
		t.Errorf("ProcessIncomingMessage() - expected [%s], actual [%s]",
			sec.AuthEngineId, expEngId)
	}
	// if len(sec.AuthKey) == 0 {
	// 	t.Error("ProcessIncomingMessage() - authKey")
	// }
	// if len(sec.PrivKey) == 0 {
	// 	t.Error("ProcessIncomingMessage() - privKey")
	// }

	// Synchronize
	smsg.SetAuthentication(true)
	smsg.SetPrivacy(true)

	err = sec.GenerateRequestMessage(snmpclient2.GetArgs(snmp), smsg)
	if err != nil {
		t.Errorf("GenerateRequestMessage() - has error %v", err)
	}
	if !bytes.Equal(smsg.UserName, expUser) {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]",
			expUser, smsg.UserName)
	}
	if !bytes.Equal(smsg.AuthEngineId, expEngId) {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]",
			expEngId, smsg.AuthEngineId)
	}
	if len(smsg.PrivParameter) == 0 {
		t.Error("GenerateRequestMessage() - privParameter")
	}
	if len(smsg.AuthParameter) == 0 {
		t.Error("GenerateRequestMessage() - authParameter")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.Report)
	rmsg = snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	rmsg.SetAuthentication(true)
	rmsg.SetPrivacy(true)
	rmsg.SetPduBytes(smsg.PduBytes())
	rmsg.AuthEngineId = []byte("foobar")
	rmsg.AuthEngineBoots = smsg.AuthEngineBoots
	rmsg.AuthEngineTime = smsg.AuthEngineTime
	rmsg.PrivParameter = smsg.PrivParameter
	rmsg.AuthParameter = smsg.AuthParameter

	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - userName check")
	}

	rmsg.UserName = expUser
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - authEngine check")
	}

	rmsg.AuthEngineId = expEngId
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err != nil {
		t.Errorf("ProcessIncomingMessage() - has error %v", err)
	}
	if sec.AuthEngineBoots != rmsg.AuthEngineBoots {
		t.Error("ProcessIncomingMessage() - engineBoots")
	}
	if sec.AuthEngineTime != rmsg.AuthEngineTime {
		t.Error("ProcessIncomingMessage() - engineTime")
	}

	// Request
	sec.AuthEngineBoots = 1
	sec.AuthEngineTime = 1

	err = sec.GenerateRequestMessage(snmpclient2.GetArgs(snmp), smsg)
	if err != nil {
		t.Errorf("GenerateRequestMessage() - has error %v", err)
	}
	if smsg.AuthEngineBoots != sec.AuthEngineBoots {
		t.Errorf("GenerateRequestMessage() - expected [%d], actual [%d]",
			sec.AuthEngineBoots, smsg.AuthEngineBoots)
	}
	if smsg.AuthEngineTime != sec.AuthEngineTime {
		t.Errorf("GenerateRequestMessage() - expected [%d], actual [%d]",
			sec.AuthEngineTime, smsg.AuthEngineTime)
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetResponse)
	spdu = pdu.(*snmpclient2.ScopedPdu)
	rmsg = snmpclient2.NewMessage(snmpclient2.V3, pdu).(*snmpclient2.MessageV3)
	rmsg.AuthEngineId = expEngId
	rmsg.AuthEngineBoots = smsg.AuthEngineBoots
	rmsg.AuthEngineTime = smsg.AuthEngineTime
	rmsg.UserName = expUser

	// set PduBytes with GetResponse
	b, _ := spdu.Marshal()
	rmsg.SetPduBytes(b)

	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - contextEngineId check")
	}

	// set PduBytes with ContextEngineId
	spdu.ContextEngineId = expCtxId
	b, _ = spdu.Marshal()
	rmsg.SetPduBytes(b)
	err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	if err == nil {
		t.Error("ProcessIncomingMessage() - contextName check")
	}

	// // set PduBytes with ContextName
	// spdu.ContextName = []byte(expCtxName)
	// b, _ = spdu.Marshal()
	// rmsg.SetPduBytes(b)
	// err = sec.ProcessIncomingMessage(snmpclient2.GetArgs(snmp), rmsg)
	// if err == nil {
	// 	t.Error("ProcessIncomingMessage() - response authenticate check")
	// }
}

func TestUsmUpdateEngineBootsTime(t *testing.T) {
	sec := snmpclient2.NewUsm().(*snmpclient2.USM)

	sec.UpdatedTime = time.Unix(time.Now().Unix()-int64(10), 0)
	err := sec.UpdateEngineBootsTime()
	if err != nil || sec.AuthEngineTime < 9 || sec.AuthEngineTime > 11 {
		t.Error("EngineBootsTime() - update authEnginetime")
	}

	sec.UpdatedTime = time.Unix(time.Now().Unix()-int64(10), 0)
	sec.AuthEngineTime = math.MaxInt32
	err = sec.UpdateEngineBootsTime()
	if err != nil || sec.AuthEngineBoots != 1 ||
		(sec.AuthEngineTime < 9 || sec.AuthEngineTime > 11) {
		t.Error("EngineBootsTime() - carry-over authEngineBoots")
	}

	sec.UpdatedTime = time.Unix(time.Now().Unix()-int64(10), 0)
	sec.AuthEngineBoots = math.MaxInt32 - 1
	sec.AuthEngineTime = math.MaxInt32
	err = sec.UpdateEngineBootsTime()
	if err == nil {
		t.Error("EngineBootsTime() - max authEngineBoots")
	}
}

func TestUsmTimeliness(t *testing.T) {
	sec := snmpclient2.NewUsm().(*snmpclient2.USM)

	err := sec.CheckTimeliness(math.MaxInt32, 0)
	if err == nil {
		t.Error("Timeliness() - max authEngineBoots")
	}

	sec.AuthEngineBoots = 1
	err = sec.CheckTimeliness(0, 0)
	if err == nil {
		t.Error("Timeliness() - lose authEngineBoots")
	}

	sec.AuthEngineBoots = 0
	err = sec.CheckTimeliness(0, 151)
	if err == nil {
		t.Error("Timeliness() - lose authEngineTime")
	}

	err = sec.CheckTimeliness(0, 150)
	if err != nil {
		t.Errorf("Timeliness() - has error %v", err)
	}
}

