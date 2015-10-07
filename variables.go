package snmpclient2

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	syntexErrorMessage = "snmp value format error, excepted format is '[type]value'," +
		" type is 'null, int32, gauge, counter32, counter64, octet, oid, ip, timeticks', value is a string. - %s"

	notError = "this is not a error. please call IsError() first."
)

func NewVariable(s string) (Variable, error) {
	if "" == s {
		return nil, fmt.Errorf("input parameter is empty.")
	}
	if s[0] != '[' {
		return nil, fmt.Errorf(syntexErrorMessage, s)
	}
	ss := strings.SplitN(s[1:], "]", 2)
	if 2 != len(ss) {
		return nil, fmt.Errorf(syntexErrorMessage, s)
	}

	switch strings.ToLower(ss[0]) {
	case "null", "nil":
		return NewNull(), nil
	case "int", "int32":
		// error pattern: return newSnmpInt32FromString(ss[1])
		// see http://www.golang.org/doc/go_faq.html#nil_error
		return NewIntegerFromString(ss[1])
	case "uint", "uint32", "gauge", "gauge32":
		return NewGauge32FromString(ss[1])
	case "counter", "counter32":
		return NewCounter32FromString(ss[1])
	case "counter64":
		return NewCounter64FromString(ss[1])
	case "octets":
		return NewOctetStringFromString(ss[1])
	case "opaque":
		return NewOpaqueFromString(ss[1])
	case "oid":
		return NewOidFromString(ss[1])
	case "ip", "ipaddress":
		return NewIPAddressFromString(ss[1])
	case "timeticks":
		return NewTimeticksFromString(ss[1])
	case "error":
		switch ss[1] {
		case "EndOfMibView":
			return NewEndOfMibView(), nil
		case "NoSucheInstance":
			return NewNoSucheInstance(), nil
		case "NoSucheObject":
			return NewNoSucheObject(), nil
		}
	}

	return nil, fmt.Errorf("unsupported snmp type -", ss[0])
}

type Variable interface {
	Int() int64
	Uint() uint64
	Bytes() []byte
	// Return a string representation of this Variable
	ToString() string
	String() string

	IsError() bool
	ErrorMessage() string

	// Return a string of type
	Syntex() int
	Marshal() ([]byte, error)
	Unmarshal([]byte) (rest []byte, err error)
}

type Integer struct {
	Value int32
}

func (v *Integer) IsError() bool {
	return false
}

func (v *Integer) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *Integer) Int() int64 {
	return int64(v.Value)
}

func (v *Integer) Uint() uint64 {
	if v.Value < 0 {
		panic(UnsupportedOperation)
	}
	return uint64(v.Value)
}

func (v *Integer) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *Integer) ToString() string {
	return strconv.FormatInt(int64(v.Value), 10)
}

func (v *Integer) String() string {
	return "[int]" + strconv.FormatInt(int64(v.Value), 10)
}

func (v *Integer) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Integer) Syntex() int {
	return SYNTAX_INTEGER
}

func (v *Integer) Marshal() ([]byte, error) {
	return asn1.Marshal(v.Value)
}

func (v *Integer) Unmarshal(b []byte) (rest []byte, err error) {
	return asn1.Unmarshal(b, &v.Value)
}

func NewInteger(i int32) *Integer {
	return &Integer{i}
}

func NewIntegerFromString(s string) (Variable, error) {
	i, ok := strconv.ParseInt(s, 10, 32)
	if nil != ok {
		return nil, fmt.Errorf("int32 style error, value is %s, exception is %s", s, ok.Error())
	}

	return &Integer{int32(i)}, nil
}

type OctetString struct {
	Value []byte
}

func (v *OctetString) IsError() bool {
	return false
}

func (v *OctetString) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *OctetString) Int() int64 {
	panic(UnsupportedOperation)
}

func (v *OctetString) Uint() uint64 {
	panic(UnsupportedOperation)
}

func (v *OctetString) Bytes() []byte {
	return v.Value
}

func (v *OctetString) ToString() string {
	//for _, c := range v.Value {
	//	if !strconv.IsPrint(rune(c)) {
	return hex.EncodeToString(v.Value) //ToHexStr(v.Value, ":")
	//	}
	//}
	//return string(v.Value)
}

func (v *OctetString) String() string {
	return "[octets]" + v.ToString()
}

func (v *OctetString) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *OctetString) Syntex() int {
	return SYNTAX_OCTETSTRING
}

func (v *OctetString) Marshal() ([]byte, error) {
	return asn1.Marshal(v.Value)
}

func (v *OctetString) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalString(b, SYNTAX_OCTETSTRING, func(s []byte) { v.Value = s })
}

func NewOctetString(b []byte) *OctetString {
	return &OctetString{b}
}

func NewOctetStringFromString(s string) (Variable, error) {
	bs, err := hex.DecodeString(s)
	if nil != err {
		return nil, err
	}
	return &OctetString{bs}, nil
}

type Null struct{}

func (v *Null) IsError() bool {
	return false
}

func (v *Null) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *Null) Int() int64 {
	panic(UnsupportedOperation)
}

func (v *Null) Uint() uint64 {
	panic(UnsupportedOperation)
}

func (v *Null) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *Null) ToString() string {
	return ""
}

func (v *Null) String() string {
	return "[null]"
}

func (v *Null) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Null) Syntex() int {
	return SYNTAX_NULL
}

func (v *Null) Marshal() ([]byte, error) {
	return []byte{SYNTAX_NULL, 0}, nil
}

func (v *Null) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalEmpty(b, SYNTAX_NULL)
}

var null = &Null{}

func NewNull() *Null {
	return null
}

type Oid struct {
	Value []int
}

func (v *Oid) IsError() bool {
	return false
}

func (v *Oid) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *Oid) Int() int64 {
	panic(UnsupportedOperation)
}

func (v *Oid) Uint() uint64 {
	panic(UnsupportedOperation)
}

func (v *Oid) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *Oid) ToString() string {
	return asn1.ObjectIdentifier(v.Value).String()
}

func (v *Oid) String() string {
	return "[oid]" + asn1.ObjectIdentifier(v.Value).String()
}

func (v *Oid) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Oid) Syntex() int {
	return SYNTAX_OID
}

func (v *Oid) Marshal() ([]byte, error) {
	return asn1.Marshal(asn1.ObjectIdentifier(v.Value))
}

func (v *Oid) Unmarshal(b []byte) (rest []byte, err error) {
	var i asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(b, &i)
	if err == nil {
		v.Value = []int(i)
	}
	return
}

// Returns true if this OID contains the specified OID
func (v *Oid) Contains(o *Oid) bool {
	if o == nil || len(v.Value) < len(o.Value) {
		return false
	}
	for i := 0; i < len(o.Value); i++ {
		if v.Value[i] != o.Value[i] {
			return false
		}
	}
	return true
}

// Returns 0 this OID is equal to the specified OID,
// -1 this OID is lexicographically less than the specified OID,
// 1 this OID is lexicographically greater than the specified OID
func (v *Oid) Compare(o *Oid) int {
	if o != nil {
		vl := len(v.Value)
		ol := len(o.Value)
		for i := 0; i < vl; i++ {
			if ol <= i || v.Value[i] > o.Value[i] {
				return 1
			} else if v.Value[i] < o.Value[i] {
				return -1
			}
		}
		if ol == vl {
			return 0
		}
	}
	return -1
}

// Returns true if this OID is same the specified OID
func (v *Oid) Equal(o *Oid) bool {
	if o == nil {
		return false
	}
	return asn1.ObjectIdentifier(v.Value).Equal(asn1.ObjectIdentifier(o.Value))
}

// Returns Oid with additional sub-ids
func (v *Oid) AppendSubIds(subs []int) Oid {
	return NewOid(append(v.Value, subs...))
}

var EmptyOID Oid

func ParseOidFromString(s string) (Oid, error) {
	ss := strings.Split(strings.Trim(s, "."), ".")
	if 2 > len(ss) {
		ss = strings.Split(strings.Trim(s, "_"), "_")
	}

	result := make([]int, 0, len(ss))
	for idx, v := range ss {
		if 0 == len(v) {
			if 0 != idx {
				return EmptyOID, fmt.Errorf("oid is syntex error, value is %s", s)
			}
			continue
		}

		if num, err := strconv.ParseUint(v, 10, 32); err == nil && num >= 0 {
			result = append(result, int(num))
			continue
		}

		if 0 != idx {
			return EmptyOID, ArgumentError{
				Value:   s,
				Message: fmt.Sprintf("The sub-identifiers is range %d..%d", 0, uint32(math.MaxUint32)),
			}
		}

		switch v {
		case "iso":
			result = append(result, 1)
		case "ccitt":
			result = append(result, 2)
		case "iso/ccitt":
			result = append(result, 3)
		case "SNMPv2-SMI::zeroDotZero":
			result = append(result, 0, 0)
		case "SNMPv2-SMI::internet":
			result = append(result, 1, 3, 6, 1)
		case "SNMPv2-SMI::experimental":
			result = append(result, 1, 3, 6, 1, 3)
		case "SNMPv2-SMI::private":
			result = append(result, 1, 3, 6, 1, 4)
		case "SNMPv2-SMI::enterprises":
			result = append(result, 1, 3, 6, 1, 4, 1)
		case "SNMPv2-SMI::security":
			result = append(result, 1, 3, 6, 1, 5)
		default:
			return EmptyOID, ArgumentError{
				Value:   s,
				Message: fmt.Sprintf("The sub-identifiers is range %d..%d", 0, uint32(math.MaxUint32)),
			}
		}
	}
	return Oid{result}, nil
}

func NewOid(oid []int) Oid {
	return Oid{oid}
}

func NewOidFromString(s string) (Variable, error) {
	if o, e := ParseOidFromString(s); nil == e {
		return &o, nil
	} else {
		return nil, e
	}
}

// MustNewOid is like NewOid but panics if argument cannot be parsed
func MustParseOidFromString(s string) Oid {
	if oid, err := ParseOidFromString(s); err != nil {
		panic(`snmpgo.MustNewOid: ` + err.Error())
	} else {
		return oid
	}
}

func ToOidString(sub []int) string {
	return asn1.ObjectIdentifier(sub).String()
}

type Oids []Oid

// Sort a Oid list
func (o Oids) Sort() Oids {
	c := make(Oids, len(o))
	copy(c, o)
	sort.Sort(sortableOids{c})
	return c
}

func (o Oids) uniq(comp func(a, b Oid) bool) Oids {
	var before Oid
	c := make(Oids, 0, len(o))
	for _, oid := range o {
		if !comp(before, oid) {
			before = oid
			c = append(c, oid)
		}
	}
	return c
}

// Filter out adjacent OID list
func (o Oids) Uniq() Oids {
	return o.uniq(func(a, b Oid) bool {
		return b.Equal(&a)
	})
}

// Filter out adjacent OID list with the same prefix
func (o Oids) UniqBase() Oids {
	return o.uniq(func(a, b Oid) bool {
		if 0 == len(a.Value) {
			return false
		}
		return b.Contains(&a)
	})
}

type sortableOids struct {
	Oids
}

func (o sortableOids) Len() int {
	return len(o.Oids)
}

func (o sortableOids) Swap(i, j int) {
	o.Oids[i], o.Oids[j] = o.Oids[j], o.Oids[i]
}

func (o sortableOids) Less(i, j int) bool {
	return o.Oids[i].Compare(&o.Oids[j]) < 1
}

func NewOids(s []string) (oids Oids, err error) {
	for _, l := range s {
		o, e := ParseOidFromString(l)
		if e != nil {
			return nil, e
		}
		oids = append(oids, o)
	}
	return
}

type Ipaddress struct {
	OctetString
}

func (v *Ipaddress) Int() int64 {
	var t uint32
	for i, b := range v.Value {
		t = t + (uint32(b) << uint(24-8*i))
	}
	return int64(t)
}

func (v *Ipaddress) Uint() uint64 {
	var t uint32
	for i, b := range v.Value {
		t = t + (uint32(b) << uint(24-8*i))
	}
	return uint64(t)
}

func (v *Ipaddress) ToString() string {
	return net.IP(v.Value).String()
}

func (v *Ipaddress) String() string {
	return "[ip]" + v.ToString()
}

func (v *Ipaddress) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Ipaddress) Syntex() int {
	return SYNTAX_IPADDRESS
}

func (v *Ipaddress) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(v.Value)
	if err == nil {
		b[0] = SYNTAX_IPADDRESS
	}
	return b, err
}

func (v *Ipaddress) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalString(b, SYNTAX_IPADDRESS, func(s []byte) { v.Value = s })
}

func NewIpaddress(a, b, c, d byte) *Ipaddress {
	return &Ipaddress{OctetString{[]byte{a, b, c, d}}}
}

func NewIPAddressFromString(s string) (Variable, error) {
	addr := net.ParseIP(s)
	if nil == addr {
		return nil, fmt.Errorf("SnmpAddress style error, value is %s", s)
	}
	addr = addr.To4()
	if nil == addr {
		return nil, fmt.Errorf("SnmpAddress style error, value is %s", s)
	}
	return &Ipaddress{OctetString{[]byte{addr[0], addr[1], addr[2], addr[3]}}}, nil
}

type Counter32 struct {
	Value uint32
}

func (v *Counter32) IsError() bool {
	return false
}

func (v *Counter32) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *Counter32) Int() int64 {
	return int64(v.Value)
}

func (v *Counter32) Uint() uint64 {
	return uint64(v.Value)
}

func (v *Counter32) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *Counter32) ToString() string {
	return strconv.FormatInt(int64(v.Value), 10)
}

func (v *Counter32) String() string {
	return "[counter32]" + strconv.FormatInt(int64(v.Value), 10)
}

func (v *Counter32) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Counter32) Syntex() int {
	return SYNTAX_COUNTER32
}

func (v *Counter32) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(int64(v.Value))
	if err == nil {
		b[0] = SYNTAX_COUNTER32
	}
	return b, err
}

func (v *Counter32) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalInt(b, SYNTAX_COUNTER32, func(s *big.Int) { v.Value = uint32(s.Int64()) })
}

func NewCounter32(i uint32) *Counter32 {
	return &Counter32{i}
}

func NewCounter32FromString(s string) (Variable, error) {
	i, ok := strconv.ParseUint(s, 10, 32)
	if nil != ok {
		return nil, fmt.Errorf("counter32 style error, value is %s, exception is %s", s, ok.Error())
	}
	return &Counter32{uint32(i)}, nil
}

type Gauge32 struct {
	Counter32
}

func (v *Gauge32) String() string {
	return "[gauge32]" + strconv.FormatInt(int64(v.Value), 10)
}

func (v *Gauge32) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Gauge32) Syntex() int {
	return SYNTAX_GAUGE32
}

func (v *Gauge32) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(int64(v.Value))
	if err == nil {
		b[0] = SYNTAX_GAUGE32
	}
	return b, err
}

func (v *Gauge32) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalInt(b, SYNTAX_GAUGE32, func(s *big.Int) { v.Value = uint32(s.Int64()) })
}

func NewGauge32(i uint32) *Gauge32 {
	return &Gauge32{Counter32{i}}
}

func NewGauge32FromString(s string) (Variable, error) {
	u32, ok := strconv.ParseUint(s, 10, 32)
	if nil != ok {
		return nil, fmt.Errorf("gauge style error, value is %s, exception is %s", s, ok.Error())
	}
	return &Gauge32{Counter32{uint32(u32)}}, nil
}

type TimeTicks struct {
	Counter32
}

func (v *TimeTicks) String() string {
	return "[timeticks]" + strconv.FormatInt(int64(v.Value), 10)
}

func (v *TimeTicks) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *TimeTicks) Syntex() int {
	return SYNTAX_TIMETICKS
}

func (v *TimeTicks) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(int64(v.Value))
	if err == nil {
		b[0] = SYNTAX_TIMETICKS
	}
	return b, err
}

func (v *TimeTicks) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalInt(b, SYNTAX_TIMETICKS, func(s *big.Int) { v.Value = uint32(s.Int64()) })
}

func NewTimeTicks(i uint32) *TimeTicks {
	return &TimeTicks{Counter32{i}}
}

func NewTimeticksFromString(s string) (Variable, error) {
	u32, ok := strconv.ParseUint(s, 10, 32)
	if nil != ok {
		return nil, fmt.Errorf("snmpTimeticks style error, value is %s, exception is %s", s, ok.Error())
	}
	return &TimeTicks{Counter32{uint32(u32)}}, nil
}

type Opaque struct {
	OctetString
}

func (v *Opaque) ToString() string {
	return ToHexStr(v.Value, ":")
}

func (v *Opaque) String() string {
	return "[opaque]" + v.ToString()
}

func (v *Opaque) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Opaque) Syntex() int {
	return SYNTAX_OPAQUE
}

func (v *Opaque) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(v.Value)
	if err == nil {
		b[0] = SYNTAX_OPAQUE
	}
	return b, err
}

func (v *Opaque) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalString(b, SYNTAX_OPAQUE, func(s []byte) { v.Value = s })
}

func NewOpaque(b []byte) *Opaque {
	return &Opaque{OctetString{b}}
}

func NewOpaqueFromString(s string) (Variable, error) {
	bs, err := hex.DecodeString(s)
	if nil != err {
		return nil, err
	}
	return &Opaque{OctetString{bs}}, nil
}

type Counter64 struct {
	Value uint64
}

func (v *Counter64) IsError() bool {
	return false
}

func (v *Counter64) ErrorMessage() string {
	panic(UnsupportedOperation)
}

func (v *Counter64) Int() int64 {
	if v.Value > math.MaxInt64 {
		panic(UnsupportedOperation)
	}
	return int64(v.Value)
}

func (v *Counter64) Uint() uint64 {
	return v.Value
}

func (v *Counter64) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *Counter64) ToString() string {
	return strconv.FormatUint(v.Value, 10)
}

func (v *Counter64) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *Counter64) String() string {
	return "[counter64]" + strconv.FormatUint(v.Value, 10)
}

func (v *Counter64) Syntex() int {
	return SYNTAX_COUNTER64
}

func (v *Counter64) Marshal() ([]byte, error) {
	i := big.NewInt(0).SetUint64(v.Value)
	b, err := asn1.Marshal(i)
	if err == nil {
		b[0] = SYNTAX_COUNTER64
	}
	return b, err
}

func (v *Counter64) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalInt(b, SYNTAX_COUNTER64, func(s *big.Int) { v.Value = s.Uint64() })
}

func NewCounter64(i uint64) *Counter64 {
	return &Counter64{i}
}

func NewCounter64FromString(s string) (Variable, error) {
	i, ok := strconv.ParseUint(s, 10, 64)
	if nil != ok {
		return nil, fmt.Errorf("counter64 style error, value is %s, exception is %s", s, ok.Error())
	}
	return &Counter64{i}, nil
}

type NoSucheObject struct {
	Null
}

func (v *NoSucheObject) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *NoSucheObject) IsError() bool {
	return true
}

func (v *NoSucheObject) ErrorMessage() string {
	return "NoSucheObject"
}

func (v *NoSucheObject) String() string {
	return "[error]NoSucheObject"
}

func (v *NoSucheObject) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *NoSucheObject) Syntex() int {
	return SYNTAX_NOSUCHOBJECT
}

func (v *NoSucheObject) Marshal() ([]byte, error) {
	return []byte{SYNTAX_NOSUCHOBJECT, 0}, nil
}

func (v *NoSucheObject) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalEmpty(b, SYNTAX_NOSUCHOBJECT)
}

var NOSUCHEOBJECT = &NoSucheObject{Null{}}

func NewNoSucheObject() *NoSucheObject {
	return NOSUCHEOBJECT
}

type NoSucheInstance struct {
	Null
}

func (v *NoSucheInstance) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *NoSucheInstance) IsError() bool {
	return true
}

func (v *NoSucheInstance) ErrorMessage() string {
	return "NoSucheInstance"
}

func (v *NoSucheInstance) String() string {
	return "[error]NoSucheInstance"
}

func (v *NoSucheInstance) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *NoSucheInstance) Syntex() int {
	return SYNTAX_NOSUCHINSTANCE
}

func (v *NoSucheInstance) Marshal() ([]byte, error) {
	return []byte{SYNTAX_NOSUCHINSTANCE, 0}, nil
}

func (v *NoSucheInstance) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalEmpty(b, SYNTAX_NOSUCHINSTANCE)
}

var NOSUCHEINSTANCE = &NoSucheInstance{Null{}}

func NewNoSucheInstance() *NoSucheInstance {
	return NOSUCHEINSTANCE
}

type EndOfMibView struct {
	Null
}

func (v *EndOfMibView) Bytes() []byte {
	panic(UnsupportedOperation)
}

func (v *EndOfMibView) IsError() bool {
	return true
}

func (v *EndOfMibView) ErrorMessage() string {
	return "EndOfMibView"
}

func (v *EndOfMibView) String() string {
	return "[error]EndOfMibView"
}

func (v *EndOfMibView) MarshalJSON() ([]byte, error) {
	return []byte("\"" + v.String() + "\""), nil
}

func (v *EndOfMibView) Syntex() int {
	return SYNTAX_ENDOFMIBVIEW
}

func (v *EndOfMibView) Marshal() ([]byte, error) {
	return []byte{SYNTAX_ENDOFMIBVIEW, 0}, nil
}

func (v *EndOfMibView) Unmarshal(b []byte) (rest []byte, err error) {
	return unmarshalEmpty(b, SYNTAX_ENDOFMIBVIEW)
}

var ENDOFMIBVIEW = &EndOfMibView{Null{}}

func NewEndOfMibView() *EndOfMibView {
	return ENDOFMIBVIEW
}

func unmarshalVariable(b []byte) (v Variable, rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}

	switch raw.Class {
	case ClassUniversal:
		switch raw.Tag {
		case SYNTAX_INTEGER:
			var u Integer
			v = &u
		case SYNTAX_OCTETSTRING:
			var u OctetString
			v = &u
		case SYNTAX_NULL:
			var u Null
			v = &u
		case SYNTAX_OID:
			var u Oid
			v = &u
		}
	case ClassApplication:
		switch raw.Tag {
		case SYNTAX_IPADDRESS & tagMask:
			var u Ipaddress
			v = &u
		case SYNTAX_COUNTER32 & tagMask:
			var u Counter32
			v = &u
		case SYNTAX_GAUGE32 & tagMask:
			var u Gauge32
			v = &u
		case SYNTAX_TIMETICKS & tagMask:
			var u TimeTicks
			v = &u
		case SYNTAX_OPAQUE & tagMask:
			var u Opaque
			v = &u
		case SYNTAX_COUNTER64 & tagMask:
			var u Counter64
			v = &u
		}
	case ClassContextSpecific:
		switch raw.Tag {
		case SYNTAX_NOSUCHOBJECT & tagMask:
			var u NoSucheObject
			v = &u
		case SYNTAX_NOSUCHINSTANCE & tagMask:
			var u NoSucheInstance
			v = &u
		case SYNTAX_ENDOFMIBVIEW & tagMask:
			var u EndOfMibView
			v = &u
		}
	}

	if v != nil {
		rest, err = v.Unmarshal(b)
		if err == nil {
			return
		}
	} else {
		err = asn1.StructuralError{fmt.Sprintf(
			"Unknown ASN.1 object : %s", ToHexStr(b, " "))}
	}

	return nil, nil, err
}

func validateUnmarshal(b []byte, tag byte) error {
	if len(b) < 1 {
		return asn1.StructuralError{"No bytes"}
	}
	if b[0] != tag {
		return asn1.StructuralError{fmt.Sprintf(
			"Invalid ASN.1 object - expected [%02x], actual [%02x] : %s",
			tag, b[0], ToHexStr(b, " "))}
	}
	return nil
}

func unmarshalEmpty(b []byte, tag byte) (rest []byte, err error) {
	err = validateUnmarshal(b, tag)
	if err != nil {
		return nil, err
	}

	var raw asn1.RawValue
	return asn1.Unmarshal(b, &raw)
}

func unmarshalInt(b []byte, tag byte, setter func(*big.Int)) (rest []byte, err error) {
	err = validateUnmarshal(b, tag)
	if err != nil {
		return nil, err
	}

	temp := b[0]
	b[0] = SYNTAX_INTEGER
	var i *big.Int
	rest, err = asn1.Unmarshal(b, &i)
	if err == nil {
		setter(i)
	}
	b[0] = temp
	return
}

func unmarshalString(b []byte, tag byte, setter func([]byte)) (rest []byte, err error) {
	err = validateUnmarshal(b, tag)
	if err != nil {
		return nil, err
	}

	temp := b[0]
	b[0] = SYNTAX_OCTETSTRING
	var s []byte
	rest, err = asn1.Unmarshal(b, &s)
	if err == nil {
		setter(s)
	}
	b[0] = temp
	return
}
