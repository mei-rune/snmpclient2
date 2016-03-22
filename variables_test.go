package snmpclient2_test

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/runner-mei/snmpclient2"
)

func TestInteger(t *testing.T) {
	expInt := int64(2147483647)
	expStr := "2147483647"
	expBuf := []byte{0x02, 0x04, 0x7f, 0xff, 0xff, 0xff}
	var v snmpclient2.Variable = snmpclient2.NewInteger(int32(expInt))

	if expInt != v.Int() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Int())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual [%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Integer
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func exceptedError1(t *testing.T, v snmpclient2.Variable) {
	defer func() {
		if o := recover(); nil == o {
			t.Errorf("Failed to call BigInt()")
		}
	}()
	v.Int()
}

func exceptedError2(t *testing.T, v snmpclient2.Variable) {
	defer func() {
		if o := recover(); nil == o {
			t.Errorf("Failed to call BigInt()")
		}
	}()
	v.Uint()
}

func exceptedError(t *testing.T, v snmpclient2.Variable) {
	exceptedError1(t, v)
	exceptedError2(t, v)
}

func TestOctetString(t *testing.T) {
	expStr := "Test"
	expBuf := []byte{0x04, 0x04, 0x54, 0x65, 0x73, 0x74}
	var v snmpclient2.Variable = snmpclient2.NewOctetString([]byte(expStr))

	//_, err := v.BigInt()
	//if err == nil {
	//	t.Errorf("Failed to call BigInt()")
	//}
	exceptedError(t, v)

	x, _ := hex.DecodeString(v.ToString())
	if expStr != string(x) {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.OctetString
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}

	x, _ = hex.DecodeString(w.ToString())
	if expStr != string(x) {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	x, _ = hex.DecodeString(w.ToString())
	if expStr != string(x) {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestNull(t *testing.T) {
	expStr := ""
	expBuf := []byte{0x05, 0x00}
	var v snmpclient2.Variable = snmpclient2.NewNull()

	exceptedError(t, v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Null
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestOid(t *testing.T) {
	expStr := "1.3.6.1.2.1.1.1.0"
	expBuf := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	var v snmpclient2.Oid

	v, err := snmpclient2.ParseOidFromString(expStr)
	if err != nil {
		t.Errorf("NewOid : %v", err)
	}

	exceptedError(t, &v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Oid
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}

	oid := snmpclient2.Oid{Value: []int{1, 3, 6, 1, 4, 1, 9, 10, 138, 1, 4, 1, 2, 1, -1073741823}}

	exceptedOid := "1.3.6.1.4.1.9.10.138.1.4.1.2.1.3221225473"
	if exceptedOid != oid.ToString() {
		t.Error("excepted is ", exceptedOid, "actual is", oid.ToString())
	}

	bs, e := oid.Marshal()
	if nil != e {
		t.Error(e)
	}

	exceptedBytes := []byte{6, 19, 43, 6, 1, 4, 1, 9, 10, 129, 10, 1, 4, 1, 2, 1, 140, 128, 128, 128, 1}
	if !bytes.Equal(bs, exceptedBytes) {
		t.Error("excepted is ", exceptedBytes, "actual is", bs)
	}

}

func TestOidOperation(t *testing.T) {
	oid, _ := snmpclient2.ParseOidFromString("1.2.3.4.5.6.7")

	oids, _ := snmpclient2.NewOids([]string{"1.2.3.4", "1.2.3.4.5.6.7",
		"1.2.3.4.5.6.7.8", "1.1.3.4", "1.3.3.4"})

	if !oid.Contains(&oids[0]) || !oid.Contains(&oids[1]) || oid.Contains(&oids[2]) ||
		oid.Contains(&oids[3]) || oid.Contains(&oids[4]) {
		t.Errorf("Failed to Contains()")
	}

	if oid.Compare(&oids[0]) != 1 || oid.Compare(&oids[1]) != 0 || oid.Compare(&oids[2]) != -1 ||
		oid.Compare(&oids[3]) != 1 || oid.Compare(&oids[4]) != -1 {
		t.Errorf("Failed to Compare()")
	}

	if oid.Equal(&oids[0]) || !oid.Equal(&oids[1]) || oid.Equal(&oids[2]) ||
		oid.Equal(&oids[3]) || oid.Equal(&oids[4]) {
		t.Errorf("Failed to Contains()")
	}

	oid = oid.AppendSubIds([]int{8, 9, 10})
	if oid.ToString() != "1.2.3.4.5.6.7.8.9.10" {
		t.Errorf("Failed to AppendSubIds()")
	}
}

func TestParseOidFromString(t *testing.T) {
	expStr := ".1.3.6.1.2.1.1.1.0"
	var v snmpclient2.Oid

	v, err := snmpclient2.ParseOidFromString(expStr)
	if err != nil {
		t.Errorf("NewOid : %v", err)
	}

	if expStr[1:] != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr[1:], v.ToString())
	}

	var s []string
	for i := 0; i <= 128; i++ {
		s = append(s, strconv.Itoa(i))
	}
	// expStr = strings.Join(s, ".")
	// v, err = snmpclient2.ParseOidFromString(expStr)
	// if err == nil {
	// 	t.Errorf("NewOid sub-identifiers size")
	// }

	expStr = "1.3.6.1.2.1.-1.0"
	v, err = snmpclient2.ParseOidFromString(expStr)
	if err == nil {
		t.Errorf("NewOid sub-identifier range")
	}

	expStr = "1.3.6.1.2.1.4294967296.0"
	v, err = snmpclient2.ParseOidFromString(expStr)
	if err == nil {
		t.Errorf("NewOid sub-identifier range")
	}

	// expStr = "3.3.6.1.2.1.1.1.0"
	// v, err = snmpclient2.ParseOidFromString(expStr)
	// if err == nil {
	// 	t.Errorf("NewOid first sub-identifier range")
	// }

	// expStr = "1"
	// v, err = snmpclient2.ParseOidFromString(expStr)
	// if err == nil {
	// 	t.Errorf("NewOid sub-identifiers size")
	// }

	// expStr = "1.40.6.1.2.1.1.1.0"
	// v, err = snmpclient2.ParseOidFromString(expStr)
	// if err == nil {
	// 	t.Errorf("NewOid first sub-identifier range")
	// }
}

func TestOids(t *testing.T) {
	oids, _ := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
	})

	expOids, _ := snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	oids = oids.Sort()
	if len(expOids) != len(oids) {
		t.Errorf("Sort() - expected [%d], actual [%d]", len(expOids), len(oids))
	}
	for i, o := range expOids {
		if !o.Equal(&oids[i]) {
			t.Errorf("Sort() - expected [%s], actual [%s]", o, oids[i])
		}
	}

	expOids, _ = snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
	})
	oids = oids.Sort().Uniq()
	if len(expOids) != len(oids) {
		t.Errorf("Uniq() - expected [%d], actual [%d]", len(expOids), len(oids))
	}
	for i, o := range expOids {
		if !o.Equal(&oids[i]) {
			t.Errorf("Uniq() - expected [%s], actual [%s]", o, oids[i])
		}
	}

	expOids, _ = snmpclient2.NewOids([]string{
		"1.3.6.1.2.1.1",
	})
	oids = oids.Sort().UniqBase()
	if len(expOids) != len(oids) {
		t.Errorf("Uniq() - expected [%d], actual [%d]", len(expOids), len(oids))
	}
	for i, o := range expOids {
		if !o.Equal(&oids[i]) {
			t.Errorf("Uniq() - expected [%s], actual [%s]", o, oids[i])
		}
	}
}

func TestIpaddress(t *testing.T) {
	expStr := "192.168.1.1"
	expInt := int64(3232235777)
	expBuf := []byte{0x40, 0x04, 0xc0, 0xa8, 0x01, 0x01}
	var v snmpclient2.Variable = snmpclient2.NewIpaddress(0xc0, 0xa8, 0x01, 0x01)

	if expInt != v.Int() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Int())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Ipaddress
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestCounter32(t *testing.T) {
	expInt := uint64(4294967295)
	expStr := "4294967295"
	expBuf := []byte{0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff}
	var v snmpclient2.Variable = snmpclient2.NewCounter32(uint32(expInt))

	if expInt != v.Uint() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Uint())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual [%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Counter32
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestGauge32(t *testing.T) {
	expInt := uint64(4294967295)
	expStr := "4294967295"
	expBuf := []byte{0x42, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff}
	var v snmpclient2.Variable = snmpclient2.NewGauge32(uint32(expInt))

	if expInt != v.Uint() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Uint())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual [%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Gauge32
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestTimeTicks(t *testing.T) {
	expInt := int64(4294967295)
	expStr := "4294967295"
	expBuf := []byte{0x43, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff}
	var v snmpclient2.Variable = snmpclient2.NewTimeTicks(uint32(expInt))

	if expInt != v.Int() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Int())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual [%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.TimeTicks
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestOpaque(t *testing.T) {
	expStr := "54:65:73:74"
	expBuf := []byte{0x44, 0x04, 0x54, 0x65, 0x73, 0x74}
	var v snmpclient2.Variable = snmpclient2.NewOpaque(expBuf[2:])

	exceptedError(t, v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Opaque
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestCounter64(t *testing.T) {
	expInt := uint64(18446744073709551615)
	expStr := "18446744073709551615"
	expBuf := []byte{0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var v snmpclient2.Variable = snmpclient2.NewCounter64(expInt)

	if expInt != v.Uint() {
		t.Errorf("BigInt() - expected [%d], actual [%d]", expInt, v.Uint())
	}

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual [%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.Counter64
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestNoSucheObject(t *testing.T) {
	expStr := ""
	expBuf := []byte{0x80, 0x00}
	var v snmpclient2.Variable = snmpclient2.NewNoSucheObject()

	exceptedError(t, v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.NoSucheObject
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestNoSucheInstance(t *testing.T) {
	expStr := ""
	expBuf := []byte{0x81, 0x00}
	var v snmpclient2.Variable = snmpclient2.NewNoSucheInstance()

	exceptedError(t, v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.NoSucheInstance
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}

func TestEndOfMibView(t *testing.T) {
	expStr := ""
	expBuf := []byte{0x82, 0x00}
	var v snmpclient2.Variable = snmpclient2.NewEndOfMibView()

	exceptedError(t, v)

	if expStr != v.ToString() {
		t.Errorf("ToString() - expected [%s], actual[%s]", expStr, v.ToString())
	}

	buf, err := v.Marshal()
	if err != nil {
		t.Errorf("Marshal(): %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpclient2.ToHexStr(expBuf, " "), snmpclient2.ToHexStr(buf, " "))
	}

	var w snmpclient2.EndOfMibView
	rest, err := (&w).Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, w.ToString())
	}

	buf = append(buf, 0x00)
	rest, err = (&w).Unmarshal(buf)
	if len(rest) != 1 || err != nil {
		t.Errorf("Unmarshal() with rest - len[%d] err[%v]", len(rest), err)
	}
	if expStr != w.ToString() {
		t.Errorf("Unmarshal() with rest - expected [%s], actual [%s]", expStr, w.ToString())
	}
}
