package snmpclient2_test

import (
	"bytes"
	"testing"

	"github.com/runner-mei/snmpclient2"
)

func testVarBind(t *testing.T, v *snmpclient2.VariableBinding, expStr string) {
	var w snmpclient2.VariableBinding
	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal() : %v", err)
	}
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.String())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.String())
	}
}

func TestVarBind(t *testing.T) {
	var v snmpclient2.VariableBinding
	oid, _ := snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	v = snmpclient2.VariableBinding{Oid: oid}

	v.Variable = snmpclient2.NewInteger(-2147483648)
	testVarBind(t, &v,
		`{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "int", "Value": "-2147483648"}}`)

	v.Variable = snmpclient2.NewOctetString([]byte("MyHost"))
	testVarBind(t, &v,
		`{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "octets", "Value": "4d79486f7374"}}`)

	v.Variable = snmpclient2.NewNull()
	testVarBind(t, &v, `{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "null", "Value": ""}}`)

	v.Variable = snmpclient2.NewCounter32(uint32(4294967295))
	testVarBind(t, &v,
		`{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "counter32", "Value": "4294967295"}}`)

	v.Variable = snmpclient2.NewCounter64(uint64(18446744073709551615))
	testVarBind(t, &v, `{"Oid": "1.3.6.1.2.1.1.1.0", `+
		`"Variable": {"Type": "counter64", "Value": "18446744073709551615"}}`)

	expBuf := []byte{0x30, 0x00}
	v = snmpclient2.VariableBinding{}
	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal() : %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	buf = []byte{0x00, 0x00}
	_, err = (&v).Unmarshal(buf)
	if err == nil {
		t.Errorf("Unmarshal() : can not validation")
	}
}

func TestVarBinds(t *testing.T) {
	var v snmpclient2.VariableBindings

	oid, _ := snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	v = append(v, snmpclient2.NewVarBind(oid, snmpclient2.NewOctetString([]byte("MyHost"))))
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.2.0")
	v = append(v, snmpclient2.NewVarBind(oid, snmpclient2.NewNull()))
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.3.0")
	v = append(v, snmpclient2.NewVarBind(oid, snmpclient2.NewTimeTicks(uint32(11111))))

	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	VariableBinding := v.MatchOid(oid)
	if VariableBinding == nil || !VariableBinding.Oid.Equal(&oid) {
		t.Errorf("Failed to MatchOid()")
	}
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.1")
	VariableBinding = v.MatchOid(oid)
	if VariableBinding != nil {
		t.Errorf("Failed to MatchOid() - no match")
	}
	VariableBinding = v.MatchOid(snmpclient2.EmptyOID)
	if VariableBinding != nil {
		t.Errorf("Failed to MatchOid() - nil")
	}

	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1")
	VariableBindings := v.MatchBaseOids(oid)
	if len(VariableBindings) != 3 {
		t.Errorf("Failed to MatchBaseOids()")
	}
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	VariableBindings = v.MatchBaseOids(oid)
	if len(VariableBindings) != 1 || !VariableBindings[0].Oid.Equal(&oid) {
		t.Errorf("Failed to MatchBaseOids() - one")
	}
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.1")
	VariableBindings = v.MatchBaseOids(oid)
	if len(VariableBindings) != 0 {
		t.Errorf("Failed to MatchBaseOids() - no match")
	}
	VariableBindings = v.MatchBaseOids(snmpclient2.EmptyOID)
	if len(VariableBindings) != 0 {
		t.Errorf("Failed to MatchBaseOids() - nil")
	}

	var w snmpclient2.VariableBindings
	for _, o := range []string{
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
	} {
		oid, _ = snmpclient2.ParseOidFromString(o)
		w = append(w, snmpclient2.NewVarBind(oid, snmpclient2.NewNull()))
	}

	expOids, _ := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	w = w.Sort()
	if len(expOids) != len(w) {
		t.Errorf("Sort() - expected [%d], actual [%d]", len(expOids), len(w))
	}
	for i, o := range expOids {
		if !o.Equal(&w[i].Oid) {
			t.Errorf("Sort() - expected [%s], actual [%s]", o, w[i].Oid)
		}
	}

	expOids, _ = snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	w = w.Sort().Uniq()
	if len(expOids) != len(w) {
		t.Errorf("Uniq() - expected [%d], actual [%d]", len(expOids), len(w))
		return
	}
	for i, o := range expOids {
		if !o.Equal(&w[i].Oid) {
			t.Errorf("Uniq() - expected [%s], actual [%s]", o, w[i].Oid)
		}
	}
}

func TestNewPdu(t *testing.T) {
	pdu := snmpclient2.NewPdu(snmpclient2.V1, snmpclient2.GetRequest)
	if _, ok := pdu.(*snmpclient2.PduV1); !ok {
		t.Errorf("NewPdu() Invalid PDU")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetRequest)
	if _, ok := pdu.(*snmpclient2.PduV1); !ok {
		t.Errorf("NewPdu() Invalid PDU")
	}

	pdu = snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetRequest)
	if _, ok := pdu.(*snmpclient2.ScopedPdu); !ok {
		t.Errorf("NewPdu() Invalid PDU")
	}
}

func TestPduV1(t *testing.T) {
	pdu := snmpclient2.NewPdu(snmpclient2.V2c, snmpclient2.GetRequest)
	pdu.SetRequestId(123)
	pdu.SetErrorStatus(snmpclient2.TooBig)
	pdu.SetErrorIndex(2)

	oid, _ := snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewOctetString([]byte("MyHost")))
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.2.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewNull())
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.3.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewTimeTicks(uint32(11111)))

	expBuf := []byte{
		0xa0, 0x3d, 0x02, 0x01, 0x7b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
		0x30, 0x32, 0x30, 0x12, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x01, 0x00, 0x04, 0x06, 0x4d, 0x79, 0x48, 0x6f, 0x73, 0x74,
		0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02,
		0x00, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x2b, 0x67,
	}
	buf, err := pdu.Marshal()
	if err != nil {
		t.Fatal("Marshal() : %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	expStr := `{"Type": "GetRequest", "RequestId": "123", ` +
		`"ErrorStatus": "TooBig", "ErrorIndex": "2", "VariableBindings": [` +
		`{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "octets", "Value": "4d79486f7374"}}, ` +
		`{"Oid": "1.3.6.1.2.1.1.2.0", "Variable": {"Type": "null", "Value": ""}}, ` +
		`{"Oid": "1.3.6.1.2.1.1.3.0", "Variable": {"Type": "timeticks", "Value": "11111"}}]}`
	var w snmpclient2.PduV1
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.String())
	}
}

func TestScopedPdu(t *testing.T) {
	pdu := snmpclient2.NewPdu(snmpclient2.V3, snmpclient2.GetRequest)
	pdu.SetRequestId(123)
	pdu.SetErrorStatus(snmpclient2.TooBig)
	pdu.SetErrorIndex(2)

	sp := pdu.(*snmpclient2.ScopedPdu)
	sp.ContextEngineId = []byte{0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	sp.ContextName = []byte("MyContext")

	oid, _ := snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.1.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewOctetString([]byte("MyHost")))
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.2.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewNull())
	oid, _ = snmpclient2.ParseOidFromString("1.3.6.1.2.1.1.3.0")
	pdu.AppendVariableBinding(oid, snmpclient2.NewTimeTicks(uint32(11111)))

	expBuf := []byte{
		0x30, 0x54, 0x04, 0x08, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x04, 0x09, 0x4d, 0x79, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
		0xa0, 0x3d, 0x02, 0x01, 0x7b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
		0x30, 0x32, 0x30, 0x12, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x01, 0x00, 0x04, 0x06, 0x4d, 0x79, 0x48, 0x6f, 0x73, 0x74,
		0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02,
		0x00, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x2b, 0x67,
	}
	buf, err := pdu.Marshal()
	if err != nil {
		t.Fatal("Marshal() : %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	expStr := `{"Type": "GetRequest", "RequestId": "123", ` +
		`"ErrorStatus": "TooBig", "ErrorIndex": "2", ` +
		`"ContextEngineId": "8001020304050607", "ContextName": "MyContext", ` +
		`"VariableBindings": [` +
		`{"Oid": "1.3.6.1.2.1.1.1.0", "Variable": {"Type": "octets", "Value": "4d79486f7374"}}, ` +
		`{"Oid": "1.3.6.1.2.1.1.2.0", "Variable": {"Type": "null", "Value": ""}}, ` +
		`{"Oid": "1.3.6.1.2.1.1.3.0", "Variable": {"Type": "timeticks", "Value": "11111"}}]}`
	var w snmpclient2.ScopedPdu
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.String())
	}
}
