package snmpclient2

import (
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"
)

type VariableBinding struct {
	Oid      *Oid
	Variable Variable
}

func (v *VariableBinding) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_SEQUENCE, IsCompound: true}

	if v.Oid == nil || v.Variable == nil {
		return asn1.Marshal(raw)
	}

	buf, err = v.Oid.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = v.Variable.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	return asn1.Marshal(raw)
}

func (v *VariableBinding) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid VariableBinding object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	var oid Oid
	next, err := (&oid).Unmarshal(raw.Bytes)
	if err != nil {
		return
	}

	variable, _, err := unmarshalVariable(next)
	if err != nil {
		return
	}

	v.Oid = &oid
	v.Variable = variable
	return
}

func (v *VariableBinding) String() string {
	var oid, vtype, value string
	if v.Oid != nil {
		oid = v.Oid.ToString()
	}
	if v.Variable != nil {
		vtype = ToSyntexString(v.Variable.Syntex())
		value = escape(v.Variable.ToString())
	}
	return fmt.Sprintf(`{"Oid": "%s", "Variable": {"Type": "%s", "Value": %s}}`,
		oid, vtype, value)
}

func NewVarBind(oid *Oid, val Variable) *VariableBinding {
	return &VariableBinding{
		Oid:      oid,
		Variable: val,
	}
}

type VariableBindings []*VariableBinding

// Gets a VariableBinding that matches
func (v VariableBindings) MatchOid(oid *Oid) *VariableBinding {
	for _, o := range v {
		if o.Oid != nil && o.Oid.Equal(oid) {
			return o
		}
	}
	return nil
}

// Gets a VariableBinding list that matches the prefix
func (v VariableBindings) MatchBaseOids(prefix *Oid) VariableBindings {
	result := make(VariableBindings, 0)
	for _, o := range v {
		if o.Oid != nil && o.Oid.Contains(prefix) {
			result = append(result, o)
		}
	}
	return result
}

// Sort a VariableBinding list by OID
func (v VariableBindings) Sort() VariableBindings {
	c := make(VariableBindings, len(v))
	copy(c, v)
	sort.Sort(sortableVarBinds{c})
	return c
}

func (v VariableBindings) uniq(comp func(a, b *VariableBinding) bool) VariableBindings {
	var before *VariableBinding
	c := make(VariableBindings, 0, len(v))
	for _, val := range v {
		if !comp(before, val) {
			before = val
			c = append(c, val)
		}
	}
	return c
}

// Filter out adjacent VariableBinding list
func (v VariableBindings) Uniq() VariableBindings {
	return v.uniq(func(a, b *VariableBinding) bool {
		if b == nil {
			return a == nil
		} else if b.Oid == nil {
			return a != nil && a.Oid == nil
		} else {
			return a != nil && b.Oid.Equal(a.Oid)
		}
	})
}

func (v VariableBindings) String() string {
	VariableBindings := make([]string, len(v))
	for i, o := range v {
		VariableBindings[i] = o.String()
	}
	return "[" + strings.Join(VariableBindings, ", ") + "]"
}

type sortableVarBinds struct {
	VariableBindings
}

func (v sortableVarBinds) Len() int {
	return len(v.VariableBindings)
}

func (v sortableVarBinds) Swap(i, j int) {
	v.VariableBindings[i], v.VariableBindings[j] = v.VariableBindings[j], v.VariableBindings[i]
}

func (v sortableVarBinds) Less(i, j int) bool {
	t := v.VariableBindings[i]
	return t != nil && t.Oid != nil && t.Oid.Compare(v.VariableBindings[j].Oid) < 1
}

// The protocol data unit of SNMP
type PDU interface {
	PduType() PduType
	RequestId() int
	SetRequestId(int)
	ErrorStatus() ErrorStatus
	SetErrorStatus(ErrorStatus)
	ErrorIndex() int
	SetErrorIndex(int)
	SetNonrepeaters(int)
	SetMaxRepetitions(int)
	AppendVarBind(*Oid, Variable)
	VariableBindings() VariableBindings
	Marshal() ([]byte, error)
	Unmarshal([]byte) (rest []byte, err error)
	String() string
}

// The PduV1 is used by SNMP V1 and V2c, other than the SNMP V1 Trap
type PduV1 struct {
	pduType          PduType
	requestId        int
	errorStatus      ErrorStatus
	errorIndex       int
	variableBindings VariableBindings
}

func (pdu *PduV1) PduType() PduType {
	return pdu.pduType
}

func (pdu *PduV1) RequestId() int {
	return pdu.requestId
}

func (pdu *PduV1) SetRequestId(i int) {
	pdu.requestId = i
}

func (pdu *PduV1) ErrorStatus() ErrorStatus {
	return pdu.errorStatus
}

func (pdu *PduV1) SetErrorStatus(i ErrorStatus) {
	pdu.errorStatus = i
}

func (pdu *PduV1) ErrorIndex() int {
	return pdu.errorIndex
}

func (pdu *PduV1) SetErrorIndex(i int) {
	pdu.errorIndex = i
}

func (pdu *PduV1) SetNonrepeaters(i int) {
	pdu.errorStatus = ErrorStatus(i)
}

func (pdu *PduV1) SetMaxRepetitions(i int) {
	pdu.errorIndex = i
}

func (pdu *PduV1) AppendVarBind(oid *Oid, variable Variable) {
	if nil == variable {
		variable = NewNull()
	}

	pdu.variableBindings = append(pdu.variableBindings, &VariableBinding{
		Oid:      oid,
		Variable: variable,
	})
}

func (pdu *PduV1) VariableBindings() VariableBindings {
	return pdu.variableBindings
}

func (pdu *PduV1) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: ClassContextSpecific, Tag: int(pdu.pduType), IsCompound: true}

	buf, err = asn1.Marshal(pdu.requestId)
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = asn1.Marshal(pdu.errorStatus)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(pdu.errorIndex)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	VariableBindings := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_SEQUENCE, IsCompound: true}
	for i := 0; i < len(pdu.variableBindings); i++ {
		buf, err = pdu.variableBindings[i].Marshal()
		if err != nil {
			return
		}
		VariableBindings.Bytes = append(VariableBindings.Bytes, buf...)
	}

	buf, err = asn1.Marshal(VariableBindings)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	return asn1.Marshal(raw)
}

func (pdu *PduV1) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}
	if raw.Class != ClassContextSpecific || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid PDU object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	next := raw.Bytes

	var requestId int
	next, err = asn1.Unmarshal(next, &requestId)
	if err != nil {
		return
	}

	var errorStatus int
	next, err = asn1.Unmarshal(next, &errorStatus)
	if err != nil {
		return
	}

	var errorIndex int
	next, err = asn1.Unmarshal(next, &errorIndex)
	if err != nil {
		return
	}

	var VariableBindings asn1.RawValue
	_, err = asn1.Unmarshal(next, &VariableBindings)
	if err != nil {
		return
	}
	if VariableBindings.Class != ClassUniversal || VariableBindings.Tag != SYNTAX_SEQUENCE || !VariableBindings.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid VariableBindings object - Class [%02x], Tag [%02x] : [%s]",
			VariableBindings.Class, VariableBindings.Tag, ToHexStr(next, " "))}
	}

	next = VariableBindings.Bytes
	for len(next) > 0 {
		var VariableBinding VariableBinding
		next, err = (&VariableBinding).Unmarshal(next)
		if err != nil {
			return
		}
		pdu.variableBindings = append(pdu.variableBindings, &VariableBinding)
	}

	pdu.pduType = PduType(raw.Tag)
	pdu.requestId = requestId
	pdu.errorStatus = ErrorStatus(errorStatus)
	pdu.errorIndex = errorIndex
	return
}

func (pdu *PduV1) String() string {
	return fmt.Sprintf(
		`{"Type": "%s", "RequestId": "%d", "ErrorStatus": "%s", `+
			`"ErrorIndex": "%d", "VariableBindings": %s}`,
		pdu.pduType, pdu.requestId, pdu.errorStatus, pdu.errorIndex,
		pdu.variableBindings.String())
}

// The ScopedPdu is used by SNMP V3.
// Includes the PduV1, and contains a SNMP context parameter
type ScopedPdu struct {
	ContextEngineId []byte
	ContextName     []byte
	PduV1
}

func (pdu *ScopedPdu) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: ClassUniversal, Tag: SYNTAX_SEQUENCE, IsCompound: true}

	buf, err = asn1.Marshal(pdu.ContextEngineId)
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = asn1.Marshal(pdu.ContextName)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = pdu.PduV1.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	return asn1.Marshal(raw)
}

func (pdu *ScopedPdu) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid ScopedPud object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	next := raw.Bytes

	var contextEngineId []byte
	next, err = asn1.Unmarshal(next, &contextEngineId)
	if err != nil {
		return
	}

	var contextName []byte
	next, err = asn1.Unmarshal(next, &contextName)
	if err != nil {
		return
	}

	var pduV1 PduV1
	_, err = (&pduV1).Unmarshal(next)
	if err != nil {
		return
	}

	pdu.ContextEngineId = contextEngineId
	pdu.ContextName = contextName
	pdu.PduV1 = pduV1
	return
}

func (pdu *ScopedPdu) String() string {
	return fmt.Sprintf(
		`{"Type": "%s", "RequestId": "%d", "ErrorStatus": "%s", "ErrorIndex": "%d", `+
			`"ContextEngineId": "%s", "ContextName": %s, "VariableBindings": %s}`,
		pdu.pduType, pdu.requestId, pdu.errorStatus, pdu.errorIndex,
		ToHexStr(pdu.ContextEngineId, ""), escape(string(pdu.ContextName)),
		pdu.variableBindings.String())
}

func NewPdu(ver SnmpVersion, t PduType) (pdu PDU) {
	p := PduV1{pduType: t}
	switch ver {
	case V1, V2c:
		pdu = &p
	case V3:
		pdu = &ScopedPdu{PduV1: p}
	}
	return
}

func NewPduWithOids(ver SnmpVersion, t PduType, oids Oids) (pdu PDU) {
	pdu = NewPdu(ver, t)
	for _, o := range oids {
		pdu.AppendVarBind(o, NewNull())
	}
	return
}

func NewPduWithVarBinds(ver SnmpVersion, t PduType, VariableBindings VariableBindings) (pdu PDU) {
	pdu = NewPdu(ver, t)
	for _, v := range VariableBindings {
		pdu.AppendVarBind(v.Oid, v.Variable)
	}
	return
}
