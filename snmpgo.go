package snmpclient2

import (
	"fmt"
	"math"
	"net"
	"time"
)

// An argument for creating a SNMP Object
type Arguments struct {
	Version          SnmpVersion   // SNMP version to use
	Timeout          time.Duration // Request timeout (The default is 5sec)
	Retries          uint          // Number of retries (The default is `0`)
	MessageMaxSize   int           // Maximum size of an SNMP message (The default is `1400`)
	Community        string        // Community (V1 or V2c specific)
	UserName         string        // Security name (V3 specific)
	SecurityLevel    SecurityLevel // Security level (V3 specific)
	AuthPassword     string        // Authentication protocol pass phrase (V3 specific)
	AuthProtocol     AuthProtocol  // Authentication protocol (V3 specific)
	AuthKey          []byte
	PrivPassword     string       // Privacy protocol pass phrase (V3 specific)
	PrivProtocol     PrivProtocol // Privacy protocol (V3 specific)
	PrivKey          []byte
	SecurityEngineId string // Security engine ID (V3 specific)
	ContextEngineId  string // Context engine ID (V3 specific)
	ContextName      string // Context name (V3 specific)
}

func (a *Arguments) setDefault() {
	// if a.Network == "" {
	// 	a.Network = "udp"
	// }
	if a.Timeout <= 0 {
		a.Timeout = timeoutDefault
	}
	if a.MessageMaxSize == 0 {
		a.MessageMaxSize = msgSizeDefault
	}
}

func (a *Arguments) validate() error {
	if v := a.Version; v != V1 && v != V2c && v != V3 {
		return ArgumentError{
			Value:   v,
			Message: "Unknown SNMP Version",
		}
	}
	// RFC3412 Section 6
	if m := a.MessageMaxSize; (m != 0 && m < msgSizeMinimum) || m > math.MaxInt32 {
		return ArgumentError{
			Value: m,
			Message: fmt.Sprintf("MessageMaxSize is range %d..%d",
				msgSizeMinimum, math.MaxInt32),
		}
	}
	if a.Version == V3 {
		// RFC3414 Section 5
		if l := len(a.UserName); l < 1 || l > 32 {
			return ArgumentError{
				Value:   a.UserName,
				Message: "UserName length is range 1..32",
			}
		}
		if a.SecurityLevel > NoAuthNoPriv {
			// RFC3414 Section 11.2
			if len(a.AuthPassword) < 8 {
				return ArgumentError{
					Value:   a.AuthPassword,
					Message: "AuthPassword is at least 8 characters in length",
				}
			}
			if p := a.AuthProtocol; !p.validate() {
				return ArgumentError{
					Value:   a.AuthProtocol,
					Message: "Illegal AuthProtocol",
				}
			}
		}
		if a.SecurityLevel > AuthNoPriv {
			// RFC3414 Section 11.2
			if len(a.PrivPassword) < 8 {
				return ArgumentError{
					Value:   a.PrivPassword,
					Message: "PrivPassword is at least 8 characters in length",
				}
			}
			if p := a.PrivProtocol; !p.validate() {
				return ArgumentError{
					Value:   a.PrivProtocol,
					Message: "Illegal PrivProtocol",
				}
			}
		}
		if a.SecurityEngineId != "" {
			a.SecurityEngineId = StripHexPrefix(a.SecurityEngineId)
			_, err := engineIdToBytes(a.SecurityEngineId)
			if err != nil {
				return err
			}
		}
		if a.ContextEngineId != "" {
			a.ContextEngineId = StripHexPrefix(a.ContextEngineId)
			_, err := engineIdToBytes(a.ContextEngineId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Arguments) String() string {
	return escape(a)
}

// SNMP Object provides functions for the SNMP Client
type SNMP struct {
	Network string
	Address string
	args    Arguments
	mp      MessageProcessing
	conn    net.Conn
}

// Open a connection
func (s *SNMP) Open() (err error) {
	if s.conn != nil {
		return
	}
	if "" == s.Network {
		s.Network = "udp"
	}

	err = retry(int(s.args.Retries), func() error {
		conn, e := net.DialTimeout(s.Network, s.Address, s.args.Timeout)
		if e == nil {
			s.conn = conn
			s.mp = NewMessageProcessing(s.args.Version)
		}
		return e
	})
	if err != nil {
		return
	}

	err = retry(int(s.args.Retries), func() error {
		if s.args.Version == V3 {
			return s.Discovery()
		}
		return nil
	})
	if err != nil {
		s.Close()
		return
	}
	return
}

// Close a connection
func (s *SNMP) Close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
		s.mp = nil
	}
}

func (s *SNMP) SetRequest(variableBindings VariableBindings) (result PDU, err error) {
	pdu := NewPduWithVarBinds(s.args.Version, SetRequest, variableBindings)

	retry(int(s.args.Retries), func() error {
		result, err = s.sendPdu(pdu)
		return err
	})
	return
}

func (s *SNMP) GetRequest(oids Oids) (result PDU, err error) {
	pdu := NewPduWithOids(s.args.Version, GetRequest, oids)

	retry(int(s.args.Retries), func() error {
		result, err = s.sendPdu(pdu)
		return err
	})
	return
}

func (s *SNMP) GetNextRequest(oids Oids) (result PDU, err error) {
	pdu := NewPduWithOids(s.args.Version, GetNextRequest, oids)

	retry(int(s.args.Retries), func() error {
		result, err = s.sendPdu(pdu)
		return err
	})
	return
}




func (s *SNMP) Discovery() error {
	err := s.Open()
	if  err != nil {
		return err
	}

	usm := s.mp.Security().(*USM)
	usm.AuthEngineId = nil
	usm.AuthEngineBoots = 0
	usm.AuthEngineTime = 0
	// usm.AuthKey = nil
	// usm.PrivKey = nil
	usm.UpdatedTime = time.Now()

	pdu := NewPduWithOids(V3, GetRequest, nil)
	pdu.SetRequestId(genRequestId())
	var sendMsg = NewMessage(V3, pdu)

	sm := sendMsg.(*MessageV3)
	sm.MessageId = genMessageId()
	sm.MessageMaxSize = s.args.MessageMaxSize
	sm.SecurityModel = securityUsm
	sm.SetReportable(confirmedType(pdu.PduType()))
	err = s.mp.Security().GenerateRequestMessage(&s.args, sendMsg)
	if err != nil {
		return err
	}

	var buf []byte
	buf, err = sendMsg.Marshal()
	if err != nil {
		return err
	}

	s.conn.SetWriteDeadline(time.Now().Add(s.args.Timeout))
	_, err = s.conn.Write(buf)
	if !confirmedType(pdu.PduType()) || err != nil {
		return err
	}

	size := s.args.MessageMaxSize
	if size < recvBufferSize {
		size = recvBufferSize
	}
	buf = make([]byte, size)
	s.conn.SetReadDeadline(time.Now().Add(s.args.Timeout))
	_, err = s.conn.Read(buf)
	if err != nil {
		return err
	}


	pdu = &ScopedPdu{}
	recvMsg := NewMessage(V3, pdu)
	_, err = recvMsg.Unmarshal(buf)
	if err != nil {
		return ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal message",
			Detail:  fmt.Sprintf("message Bytes - [%s]", ToHexStr(buf, " ")),
		}
	}

	rm := recvMsg.(*MessageV3)
	if sm.Version() != rm.Version() {
		return ResponseError{
			Message: fmt.Sprintf(
				"SnmpVersion mismatch - expected [%v], actual [%v]", sm.Version(), rm.Version()),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}
	if sm.MessageId != rm.MessageId {
		return ResponseError{
			Message: fmt.Sprintf(
				"MessageId mismatch - expected [%d], actual [%d]", sm.MessageId, rm.MessageId),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}

	usm.AuthEngineId = rm.AuthEngineId
	usm.AuthEngineBoots = rm.AuthEngineBoots
	usm.AuthEngineTime = rm.AuthEngineTime
	usm.UpdatedTime = time.Now()
	return nil
}

func (s *SNMP) GetBulkRequest(oids Oids, nonRepeaters, maxRepetitions int) (result PDU, err error) {
	if s.args.Version < V2c {
		return nil, ArgumentError{
			Value:   s.args.Version,
			Message: "Unsupported SNMP Version",
		}
	}
	// RFC 3416 Section 3
	if nonRepeaters < 0 || nonRepeaters > math.MaxInt32 {
		return nil, ArgumentError{
			Value:   nonRepeaters,
			Message: fmt.Sprintf("NonRepeaters is range %d..%d", 0, math.MaxInt32),
		}
	}
	if maxRepetitions < 0 || maxRepetitions > math.MaxInt32 {
		return nil, ArgumentError{
			Value:   maxRepetitions,
			Message: fmt.Sprintf("NonRepeaters is range %d..%d", 0, math.MaxInt32),
		}
	}

	pdu := NewPduWithOids(s.args.Version, GetBulkRequest, oids)
	pdu.SetNonrepeaters(nonRepeaters)
	pdu.SetMaxRepetitions(maxRepetitions)

	retry(int(s.args.Retries), func() error {
		result, err = s.sendPdu(pdu)
		return err
	})
	return
}

// This method inquire about OID subtrees by repeatedly using GetBulkRequest.
// Returned PDU contains the VariableBinding list of all subtrees.
// however, if the ErrorStatus of PDU is not the NoError, return only the last query result.
func (s *SNMP) GetBulkWalk(oids Oids, nonRepeaters, maxRepetitions int) (result PDU, err error) {
	var nonRepBinds, resBinds VariableBindings

	oids = append(oids[:nonRepeaters], oids[nonRepeaters:].Sort().UniqBase()...)
	reqOids := make(Oids, len(oids))
	copy(reqOids, oids)

	for len(reqOids) > 0 {
		pdu, err := s.GetBulkRequest(reqOids, nonRepeaters, maxRepetitions)
		if err != nil {
			return nil, err
		}
		if s := pdu.ErrorStatus(); s != NoError &&
			(s != NoSuchName || pdu.ErrorIndex() <= nonRepeaters) {
			return pdu, nil
		}

		VariableBindings := pdu.VariableBindings()

		if nonRepeaters > 0 {
			nonRepBinds = append(nonRepBinds, VariableBindings[:nonRepeaters]...)
			VariableBindings = VariableBindings[nonRepeaters:]
			oids = oids[nonRepeaters:]
			reqOids = reqOids[nonRepeaters:]
			nonRepeaters = 0
		}

		filled := len(VariableBindings) == len(reqOids)*maxRepetitions
		VariableBindings = VariableBindings.Sort().Uniq()

		for i, _ := range reqOids {
			matched := VariableBindings.MatchBaseOids(oids[i])
			mLength := len(matched)

			if mLength == 0 || resBinds.MatchOid(matched[mLength-1].Oid) != nil {
				reqOids[i] = NewOid(nil)
				continue
			}

			hasError := false
			for _, val := range matched {
				switch val.Variable.(type) {
				case *NoSucheObject, *NoSucheInstance, *EndOfMibView:
					hasError = true
				default:
					resBinds = append(resBinds, val)
					reqOids[i] = val.Oid
				}
			}

			if hasError || (filled && mLength < maxRepetitions) {
				reqOids[i] = NewOid(nil)
			}
		}

		// sweep completed oids
		for i := len(reqOids) - 1; i >= 0; i-- {
			if reqOids[i].Value == nil {
				reqOids = append(reqOids[:i], reqOids[i+1:]...)
				oids = append(oids[:i], oids[i+1:]...)
			}
		}
	}

	resBinds = append(nonRepBinds, resBinds.Sort().Uniq()...)
	return NewPduWithVarBinds(s.args.Version, GetResponse, resBinds), nil
}

func (s *SNMP) V2Trap(VariableBindings VariableBindings) error {
	return s.v2trap(SNMPTrapV2, VariableBindings)
}

func (s *SNMP) V1Trap(enterprise Oid, agentAddress Ipaddress, genericTrap int,
	specificTrap int, VariableBindings VariableBindings) error {
	if s.args.Version != V1 {
		return ArgumentError{
			Value:   s.args.Version,
			Message: "Unsupported SNMP Version",
		}
	}

	pdu := NewPduWithVarBinds(s.args.Version, Trap, VariableBindings).(*PduV1)
	pdu.Enterprise = enterprise
	pdu.AgentAddress = agentAddress
	pdu.GenericTrap = genericTrap
	pdu.SpecificTrap = specificTrap
	pdu.Timestamp = 0

	var err error
	retry(int(s.args.Retries), func() error {
		_, err = s.sendPdu(pdu)
		return err
	})
	return err
}

func (s *SNMP) InformRequest(VariableBindings VariableBindings) error {
	return s.v2trap(InformRequest, VariableBindings)
}

func (s *SNMP) v2trap(pduType PduType, VariableBindings VariableBindings) (err error) {
	if s.args.Version < V2c {
		return ArgumentError{
			Value:   s.args.Version,
			Message: "Unsupported SNMP Version",
		}
	}

	pdu := NewPduWithVarBinds(s.args.Version, pduType, VariableBindings)

	retry(int(s.args.Retries), func() error {
		_, err = s.sendPdu(pdu)
		return err
	})
	return
}

func (s *SNMP) sendPdu(pdu PDU) (result PDU, err error) {
	if err = s.Open(); err != nil {
		return
	}

	var sendMsg Message
	sendMsg, err = s.mp.PrepareOutgoingMessage(s, pdu)
	if err != nil {
		return
	}

	var buf []byte
	buf, err = sendMsg.Marshal()
	if err != nil {
		return
	}

	s.conn.SetWriteDeadline(time.Now().Add(s.args.Timeout))
	_, err = s.conn.Write(buf)
	if !confirmedType(pdu.PduType()) || err != nil {
		return
	}

	size := s.args.MessageMaxSize
	if size < recvBufferSize {
		size = recvBufferSize
	}
	buf = make([]byte, size)
	s.conn.SetReadDeadline(time.Now().Add(s.args.Timeout))
	_, err = s.conn.Read(buf)
	if err != nil {
		return
	}

	result, err = s.mp.PrepareDataElements(s, sendMsg, buf)
	if result != nil && len(pdu.VariableBindings()) != 0 {
		if err = s.checkPdu(result); err != nil {
			result = nil
		}
	}
	return
}

func (s *SNMP) checkPdu(pdu PDU) (err error) {
	VariableBindings := pdu.VariableBindings()
	if s.args.Version == V3 && pdu.PduType() == Report && len(VariableBindings) > 0 {
		oid := VariableBindings[0].Oid.ToString()
		rep := reportStatusOid(oid)
		err = ResponseError{
			Message: fmt.Sprintf("Received a report from the agent - %s(%s)", rep, oid),
			Detail:  fmt.Sprintf("PDU - %s", pdu),
		}
		// perhaps the agent has rebooted after the previous communication
		if rep == usmStatsNotInTimeWindows {
			err = notInTimeWindowError{err.(ResponseError)}
		}
	}
	return
}

func (s *SNMP) String() string {
	if s.conn == nil {
		return fmt.Sprintf(`{"conn": false, "args": %s}`, s.args.String())
	} else {
		return fmt.Sprintf(`{"conn": true, "args": %s, "security": %s}`,
			s.args.String(), s.mp.Security().String())
	}
}

// Create a SNMP Object
func NewSNMP(network, address string, args Arguments) (*SNMP, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	args.setDefault()
	return &SNMP{Network: network,
		Address: address,
		args:    args}, nil
}
