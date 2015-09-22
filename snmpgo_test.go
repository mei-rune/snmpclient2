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
		AuthProtocol:  snmpclient2.Md5,
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
		AuthProtocol:  snmpclient2.Md5,
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
		AuthProtocol:  snmpclient2.Md5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpclient2.Des,
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
		AuthProtocol:  snmpclient2.Md5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpclient2.Des,
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
