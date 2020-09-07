package snmpclient2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/runner-mei/snmpclient2/asn1"
)

// The protocol data unit of SNMP
// The PduV1 is used by SNMP V1 and V2c, other than the SNMP V1 Trap
//
// trap pdu
// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
// |  PDU Type  |  enterprise  | agent addr |  generic trap  | specific trap | time stamp  |  variable bindings  |
// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
//
// reponse pdu
// +------------+--------------+----------------+---------------+----------------------+
// |  PDU Type  |  request id  |  error status  |  error index  |   variable bindings  |
// +------------+--------------+----------------+---------------+----------------------+
//
// request pdu
// +------------+--------------+----------------+---------------+----------------------+
// |  PDU Type  |  request id  |       0        |       0       |   variable bindings  |
// +------------+--------------+----------------+---------------+----------------------+
//

//                  +-------------------------------------------------------------------------------------------------------+
// snmpv1 message   | version  | community |                                           PDU                                  |
//                  +-------------------------------------------------------------------------------------------------------+
//
// snmpv2 message    same as v1
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
//  snmpv1 get/next/set PDU
//                  +-------------------------------------------------------------------------------------------------------+
//                  | PDU type  | RequestID |      0       |      0       |                 variable bindings               |
//                  +-------------------------------------------------------------------------------------------------------+
//
//  snmpv1 response PDU
//                  +-------------------------------------------------------------------------------------------------------+
//                  | PDU type  | RequestID | error status | error index  |                 variable bindings               |
//                  +-------------------------------------------------------------------------------------------------------+
//
//  snmpv1 trap PDU
//                  +-------------------------------------------------------------------------------------------------------+
//                  | PDU type  | enterprise | agent addr | generic trap  | specific trap | timestamp |  variable bindings  |
//                  +-------------------------------------------------------------------------------------------------------+
//
//  snmpv2 trap PDU                                                 |<---------------- variable bindings ------------------>|
//                  +-------------------------------------------------------------------------------------------------------+
//                  | PDU type  | RequestID |     0     |     0     | sysUptime.0 | value   | snmpTrap oid.0 | value2 | ... |
//                  +-------------------------------------------------------------------------------------------------------+
//
//
//  variable bindings
//                  +-------------------------------------------------------------------------------------------------------+
//                  | name1  | value1 | name2 | value2  |               ...                               | namen | valuen  |
//                  +-------------------------------------------------------------------------------------------------------+

type VariableBinding struct {
	Oid      Oid
	Variable Variable
}

func (v *VariableBinding) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}

	if v.Variable == nil {
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
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
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

	v.Oid = oid
	v.Variable = variable
	return
}

func (v *VariableBinding) String() string {
	var vtype, value string

	if v.Variable != nil {
		vtype = ToSyntexString(v.Variable.Syntex())
		value = escape(v.Variable.ToString())
	}
	return fmt.Sprintf(`{"Oid": "%s", "Variable": {"Type": "%s", "Value": %s}}`,
		v.Oid.ToString(), vtype, value)
}

func NewVarBind(oid Oid, val Variable) VariableBinding {
	return VariableBinding{
		Oid:      oid,
		Variable: val,
	}
}

type VariableBindings []VariableBinding

// Gets a VariableBinding that matches
func (v VariableBindings) MatchOid(oid Oid) *VariableBinding {
	for _, o := range v {
		if o.Oid.Equal(&oid) {
			return &o
		}
	}
	return nil
}

// Gets a VariableBinding list that matches the prefix
func (v VariableBindings) MatchBaseOids(prefix Oid) VariableBindings {
	if 0 == len(prefix.Value) {
		return VariableBindings{}
	}
	result := make(VariableBindings, 0)
	for _, o := range v {
		if o.Oid.Contains(&prefix) {
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

func (v VariableBindings) uniq(comp func(a, b VariableBinding) bool) VariableBindings {
	var before VariableBinding
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
	return v.uniq(func(a, b VariableBinding) bool {
		return b.Oid.Equal(&a.Oid)
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
	return v.VariableBindings[i].Oid.Compare(&v.VariableBindings[j].Oid) < 1
}

// The protocol data unit of SNMP
// The PduV1 is used by SNMP V1 and V2c, other than the SNMP V1 Trap
//
// trap pdu
// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
// |  PDU Type  |  enterprise  | agent addr |  generic trap  | specific trap | time stamp  |  variable bindings  |
// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
//
// reponse pdu
// +------------+--------------+----------------+---------------+----------------------+
// |  PDU Type  |  request id  |  error status  |  error index  |   variable bindings  |
// +------------+--------------+----------------+---------------+----------------------+
//
// request pdu
// +------------+--------------+----------------+---------------+----------------------+
// |  PDU Type  |  request id  |       0        |       0       |   variable bindings  |
// +------------+--------------+----------------+---------------+----------------------+
//
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
	AppendVariableBinding(Oid, Variable)
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
	Enterprise       Oid
	AgentAddress     Ipaddress
	GenericTrap      int
	SpecificTrap     int
	Timestamp        int
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

func (pdu *PduV1) AppendVariableBinding(oid Oid, variable Variable) {
	if nil == variable {
		variable = NewNull()
	}

	pdu.variableBindings = append(pdu.variableBindings, VariableBinding{
		Oid:      oid,
		Variable: variable,
	})
}

func (pdu *PduV1) VariableBindings() VariableBindings {
	return pdu.variableBindings
}

func (pdu *PduV1) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: int(pdu.pduType), IsCompound: true}

	if Trap == pdu.pduType {
		buf, err = pdu.Enterprise.Marshal()
		if err != nil {
			return
		}
		raw.Bytes = buf

		buf, err = pdu.AgentAddress.Marshal()
		if err != nil {
			return
		}
		raw.Bytes = append(raw.Bytes, buf...)

		buf, err = asn1.Marshal(pdu.GenericTrap)
		if err != nil {
			return
		}
		raw.Bytes = append(raw.Bytes, buf...)

		buf, err = asn1.Marshal(pdu.SpecificTrap)
		if err != nil {
			return
		}
		raw.Bytes = append(raw.Bytes, buf...)

		buf, err = asn1.Marshal(pdu.Timestamp)
		if err != nil {
			return
		}
		raw.Bytes = append(raw.Bytes, buf...)
	} else {
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
	}

	VariableBindings := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}
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
	if raw.Class != asn1.ClassContextSpecific || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid PDU object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, ToHexStr(b, " "))}
	}

	var requestId int
	var errorStatus int
	var errorIndex int
	var enterprise Oid
	var agentAddress Ipaddress
	var genericTrap int
	var specificTrap int
	var timestamp int

	next := raw.Bytes

	// The protocol data unit of SNMP
	// The PduV1 is used by SNMP V1 and V2c, other than the SNMP V1 Trap
	//
	// trap pdu
	// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
	// |  PDU Type  |  enterprise  | agent addr |  generic trap  | specific trap | time stamp  |  variable bindings  |
	// +------------+--------------+------------+----------------+---------------+-------------+---------------------+
	//
	// reponse pdu
	// +------------+--------------+----------------+---------------+----------------------+
	// |  PDU Type  |  request id  |  error status  |  error index  |   variable bindings  |
	// +------------+--------------+----------------+---------------+----------------------+
	//
	// request pdu
	// +------------+--------------+----------------+---------------+----------------------+
	// |  PDU Type  |  request id  |       0        |       0       |   variable bindings  |
	// +------------+--------------+----------------+---------------+----------------------+
	//

	if Trap == PduType(raw.Tag) {
		next, err = enterprise.Unmarshal(next)
		if err != nil {
			return
		}

		next, err = agentAddress.Unmarshal(next)
		if err != nil {
			return
		}

		next, err = asn1.Unmarshal(next, &genericTrap)
		if err != nil {
			return
		}

		next, err = asn1.Unmarshal(next, &specificTrap)
		if err != nil {
			return
		}
		var t asn1.RawValue
		next, err = asn1.Unmarshal(next, &t)
		if err != nil {
			return
		}
	} else {
		next, err = asn1.Unmarshal(next, &requestId)
		if err != nil {
			return
		}

		next, err = asn1.Unmarshal(next, &errorStatus)
		if err != nil {
			return
		}

		next, err = asn1.Unmarshal(next, &errorIndex)
		if err != nil {
			return
		}
	}

	var VariableBindings asn1.RawValue
	_, err = asn1.Unmarshal(next, &VariableBindings)
	if err != nil {
		return
	}
	if VariableBindings.Class != asn1.ClassUniversal || VariableBindings.Tag != asn1.TagSequence || !VariableBindings.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid VariableBindings object - Class [%02x], Tag [%02x] : [%s]",
			VariableBindings.Class, VariableBindings.Tag, ToHexStr(next, " "))}
	}

	next = VariableBindings.Bytes
	for len(next) > 0 {
		var variableBinding VariableBinding
		next, err = variableBinding.Unmarshal(next)
		if err != nil {
			return
		}
		pdu.variableBindings = append(pdu.variableBindings, variableBinding)
	}

	pdu.pduType = PduType(raw.Tag)
	pdu.requestId = requestId
	pdu.errorStatus = ErrorStatus(errorStatus)
	pdu.errorIndex = errorIndex

	pdu.Enterprise = enterprise
	pdu.AgentAddress = agentAddress
	pdu.GenericTrap = genericTrap
	pdu.SpecificTrap = specificTrap
	pdu.Timestamp = timestamp
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
	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}

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
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
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
		pdu.AppendVariableBinding(o, NewNull())
	}
	return
}

func NewPduWithVarBinds(ver SnmpVersion, t PduType, VariableBindings VariableBindings) (pdu PDU) {
	pdu = NewPdu(ver, t)
	for _, v := range VariableBindings {
		pdu.AppendVariableBinding(v.Oid, v.Variable)
	}
	return
}
