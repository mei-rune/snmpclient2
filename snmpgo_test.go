package snmpclient2_test

import (
	"math"
	"testing"

	"github.com/runner-mei/snmpclient2"
)

func TestSNMPArguments(t *testing.T) {
	args := &snmpclient2.Arguments{Version: 2}
	err := snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - version check")
	}

	args = &snmpclient2.Arguments{MessageMaxSize: -1}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - message size(min)")
	}

	args = &snmpclient2.Arguments{MessageMaxSize: math.MaxInt32 + 1}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - message size(max)")
	}

	args = &snmpclient2.Arguments{Version: snmpclient2.V3}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - user name")
	}

	args = &snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthNoPriv,
	}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - auth password")
	}

	args = &snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthNoPriv,
		AuthPassword:  "aaaaaaaa",
	}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - auth protocol")
	}

	args = &snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpclient2.MD5,
	}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - priv password")
	}

	args = &snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpclient2.MD5,
		PrivPassword:  "bbbbbbbb",
	}
	err = snmpclient2.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - priv protocol")
	}

	args = &snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpclient2.MD5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpclient2.DES,
	}
	err = snmpclient2.ArgsValidate(args)
	if err != nil {
		t.Errorf("validate() - has error %v", err)
	}
}

func TestSNMP(t *testing.T) {
	snmp, _ := snmpclient2.NewSNMP("udp", "127.0.0.1", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "MyName",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpclient2.MD5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpclient2.DES,
	})

	pdu := snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.Report)
	err := snmpclient2.SnmpCheckPdu(snmp, pdu)
	if err != nil {
		t.Errorf("checkPdu() - has error %v", err)
	}

	oids, _ := snmpclient2.NewOids([]string{"1.3.6.1.6.3.11.2.1.1.0"})
	pdu = snmpclient2.NewPduWithOids(snmpclient2.V3, snmpclient2.Report, oids)
	err = snmpclient2.SnmpCheckPdu(snmp, pdu)
	if err == nil {
		t.Error("checkPdu() - report oid")
	}
}

// 安全级别：authpriv 安全名：mfk2 授权方式：MD5 授权密码：mfk123456 加密方式：DES 加密密码：mfk123456
// 安全级别：authpriv 安全名：mfk3 授权方式：SHA 授权密码：mfk123456 加密方式：AES 加密密码：mfk123456 

func TestSNMPGetDES(t *testing.T) {
	snmp, err := snmpclient2.NewSNMP("udp", "127.0.0.1:161", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "mfk2",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthProtocol:  snmpclient2.MD5,
		AuthPassword:  "mfk1!@#$&",
		PrivProtocol:   snmpclient2.DES,
		PrivPassword:  "mfk1!@#$&",
	})
	if err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}
	defer snmp.Close()
	
	if err = snmp.Discovery(); err != nil {
		// Failed to open connection
		t.Error(err)
		return
	}

	oids, err := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	if err != nil {
		// Failed to parse Oids
		t.Error(err)
		return
	}

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		t.Error(err)
		return
	}
	if pdu.ErrorStatus() != snmpclient2.NoError {
		// Received an error from the agent
		t.Error(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VariableBinding list
	t.Log(pdu.VariableBindings())

	// select a VariableBinding
	t.Log(pdu.VariableBindings().MatchOid(oids[0]))
}


func TestSNMPGetAES(t *testing.T) {
	snmp, err := snmpclient2.NewSNMP("udp", "127.0.0.1:161", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "mfk3",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthProtocol:  snmpclient2.SHA,
		AuthPassword:  "mfk1!@#$&",
		PrivProtocol:   snmpclient2.AES,
		PrivPassword:  "mfk1!@#$&",
	})
	if err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}
	defer snmp.Close()
	
	if err = snmp.Discovery(); err != nil {
		// Failed to open connection
		t.Error(err)
		return
	}

	oids, err := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	if err != nil {
		// Failed to parse Oids
		t.Error(err)
		return
	}

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		t.Error(err)
		return
	}
	if pdu.ErrorStatus() != snmpclient2.NoError {
		// Received an error from the agent
		t.Error(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VariableBinding list
	t.Log(pdu.VariableBindings())

	// select a VariableBinding
	t.Log(pdu.VariableBindings().MatchOid(oids[0]))
}


func TestSNMPGetAES192(t *testing.T) {
	snmp, err := snmpclient2.NewSNMP("udp", "127.0.0.1:161", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "authSHA384PrivAES192User",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthProtocol:  snmpclient2.SHA384,
		AuthPassword:  "testingpass7323456",
		PrivProtocol:   snmpclient2.AES192,
		PrivPassword:  "testingpass7223456",
	})
	if err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}
	defer snmp.Close()
	
	if err = snmp.Discovery(); err != nil {
		// Failed to open connection
		t.Error(err)
		return
	}

	oids, err := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	if err != nil {
		// Failed to parse Oids
		t.Error(err)
		return
	}

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		t.Error(err)
		return
	}
	if pdu.ErrorStatus() != snmpclient2.NoError {
		// Received an error from the agent
		t.Error(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VariableBinding list
	t.Log(pdu.VariableBindings())

	// select a VariableBinding
	t.Log(pdu.VariableBindings().MatchOid(oids[0]))
}

func TestSNMPGetAES256(t *testing.T) {
	snmp, err := snmpclient2.NewSNMP("udp", "127.0.0.1:161", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "authSHA512PrivAES256User",
		SecurityLevel: snmpclient2.AuthPriv,
		AuthProtocol:  snmpclient2.SHA512,
		AuthPassword:  "testingpass7423456",
		PrivProtocol:   snmpclient2.AES256,
		PrivPassword:  "testingpass7423456",
	})
	if err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}
	defer snmp.Close()
	
	if err = snmp.Discovery(); err != nil {
		// Failed to open connection
		t.Error(err)
		return
	}

	oids, err := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	if err != nil {
		// Failed to parse Oids
		t.Error(err)
		return
	}

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		t.Error(err)
		return
	}
	if pdu.ErrorStatus() != snmpclient2.NoError {
		// Received an error from the agent
		t.Error(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VariableBinding list
	t.Log(pdu.VariableBindings())

	// select a VariableBinding
	t.Log(pdu.VariableBindings().MatchOid(oids[0]))
}


func TestSNMPGetSha512(t *testing.T) {
	snmp, err := snmpclient2.NewSNMP("udp", "127.0.0.1:161", snmpclient2.Arguments{
		Version:       snmpclient2.V3,
		UserName:      "authSHA512OnlyUser",
		SecurityLevel: snmpclient2.AuthNoPriv,
		AuthPassword:  "testingpass5423456",
		AuthProtocol:  snmpclient2.SHA512,
	})
	if err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.Log(err)
		return
	}
	defer snmp.Close()
	
	if err = snmp.Discovery(); err != nil {
		// Failed to open connection
		t.Error(err)
		return
	}

	oids, err := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	if err != nil {
		// Failed to parse Oids
		t.Error(err)
		return
	}

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		t.Error(err)
		return
	}
	if pdu.ErrorStatus() != snmpclient2.NoError {
		// Received an error from the agent
		t.Error(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VariableBinding list
	t.Log(pdu.VariableBindings())

	// select a VariableBinding
	t.Log(pdu.VariableBindings().MatchOid(oids[0]))
}
