package snmpclient2

import (
	"strconv"
	"time"

	"github.com/runner-mei/snmpclient2/asn1"
)

type SnmpVersion int

const (
	V1  SnmpVersion = 0
	V2c SnmpVersion = 1
	V3  SnmpVersion = 3
)

func (s SnmpVersion) String() string {
	switch s {
	case V1:
		return "1"
	case V2c:
		return "2c"
	case V3:
		return "3"
	default:
		return "unknown_version"
	}
}

func (s SnmpVersion) ToString() string {
	switch s {
	case V1:
		return "v1"
	case V2c:
		return "v2c"
	case V3:
		return "v3"
	default:
		return "unknown_version"
	}
}

type PduType int

const (
	GetRequest PduType = iota
	GetNextRequest
	GetResponse
	SetRequest
	Trap
	GetBulkRequest
	InformRequest
	SNMPTrapV2
	Report
)

func (t PduType) String() string {
	switch t {
	case GetRequest:
		return "GetRequest"
	case GetNextRequest:
		return "GetNextRequest"
	case GetResponse:
		return "GetResponse"
	case SetRequest:
		return "SetRequest"
	case Trap:
		return "Trap"
	case GetBulkRequest:
		return "GetBulkRequest"
	case InformRequest:
		return "InformRequest"
	case SNMPTrapV2:
		return "SNMPTrapV2"
	case Report:
		return "Report"
	default:
		return "Unknown"
	}
}

type ErrorStatus int

const (
	NoError ErrorStatus = iota
	TooBig
	NoSuchName
	BadValue
	ReadOnly
	GenError
	NoAccess
	WrongType
	WrongLength
	WrongEncoding
	WrongValue
	NoCreation
	InconsistentValue
	ResourceUnavailable
	CommitFailed
	UndoFailed
	AuthorizationError
	NotWritable
	InconsistentName
)

func (e ErrorStatus) String() string {
	switch e {
	case NoError:
		return "NoError"
	case TooBig:
		return "TooBig"
	case NoSuchName:
		return "NoSuchName"
	case BadValue:
		return "BadValue"
	case ReadOnly:
		return "ReadOnly"
	case GenError:
		return "GenError"
	case NoAccess:
		return "NoAccess"
	case WrongType:
		return "WrongType"
	case WrongLength:
		return "WrongLength"
	case WrongEncoding:
		return "WrongEncoding"
	case WrongValue:
		return "WrongValue"
	case NoCreation:
		return "NoCreation"
	case InconsistentValue:
		return "InconsistentValue"
	case ResourceUnavailable:
		return "ResourceUnavailable"
	case CommitFailed:
		return "CommitFailed"
	case UndoFailed:
		return "UndoFailed"
	case AuthorizationError:
		return "AuthorizationError"
	case NotWritable:
		return "NotWritable"
	case InconsistentName:
		return "InconsistentName"
	default:
		return "Unknown"
	}
}

const (
	timeoutDefault = 5 * time.Second
	recvBufferSize = 1 << 11
	msgSizeDefault = 1400
	msgSizeMinimum = 484
	tagMask        = 0x1f
	mega           = 1 << 20
)

// // ASN.1 Class
// const (
// 	ClassUniversal = iota
// 	ClassApplication
// 	ClassContextSpecific
// 	ClassPrivate
// )

// ASN.1 Tag
const (
// asn1.TagInteger        = 0x02
// asn1.TagOctetString    = 0x04
// asn1.TagNull           = 0x05
// asn1.TagOID            = 0x06
// asn1.TagSequence       = 0x10
// asn1.TagIPAddress      = 0x40
// asn1.TagCounter32      = 0x41
// asn1.TagGauge32        = 0x42
// asn1.TagTimeticks      = 0x43
// asn1.TagOpaque         = 0x44
// asn1.TagCounter64      = 0x46
// asn1.TagNoSuchObject   = 0x80
// asn1.TagNoSuchInstance = 0x81
// asn1.TagEndOfMibView   = 0x82
)

func ToSyntexString(t int) string {
	switch t {
	case asn1.TagInteger:
		return "int"
	case asn1.TagOctetString:
		return "octets"
	case asn1.TagNull:
		return "null"
	case asn1.TagOID:
		return "oid"
	case asn1.TagSequence:
		return "sequence"
	case asn1.TagIPAddress:
		return "ip"
	case asn1.TagCounter32:
		return "counter32"
	case asn1.TagGauge32:
		return "gauge32"
	case asn1.TagTimeticks:
		return "timeticks"
	case asn1.TagOpaque:
		return "opaque"
	case asn1.TagCounter64:
		return "counter64"
	case asn1.TagNoSuchObject:
		return "NOSUCHOBJECT"
	case asn1.TagNoSuchInstance:
		return "NOSUCHINSTANCE"
	case asn1.TagEndOfMibView:
		return "ENDOFMIBVIEW"
	default:
		return strconv.FormatInt(int64(t), 10)
	}
}

type reportStatusOid string

const (
	// RFC 3412 Section 5
	snmpUnknownSecurityModels reportStatusOid = "1.3.6.1.6.3.11.2.1.1.0"
	snmpInvalidMsgs           reportStatusOid = "1.3.6.1.6.3.11.2.1.2.0"
	snmpUnknownPDUHandlers    reportStatusOid = "1.3.6.1.6.3.11.2.1.3.0"
	// RFC 3413 Section 4.1.2
	snmpUnavailableContexts reportStatusOid = "1.3.6.1.6.3.12.1.4.0"
	snmpUnknownContexts     reportStatusOid = "1.3.6.1.6.3.12.1.5.0"
	// RFC 3414 Section 5
	usmStatsUnsupportedSecLevels reportStatusOid = "1.3.6.1.6.3.15.1.1.1.0"
	usmStatsNotInTimeWindows     reportStatusOid = "1.3.6.1.6.3.15.1.1.2.0"
	usmStatsUnknownUserNames     reportStatusOid = "1.3.6.1.6.3.15.1.1.3.0"
	usmStatsUnknownEngineIDs     reportStatusOid = "1.3.6.1.6.3.15.1.1.4.0"
	usmStatsWrongDigests         reportStatusOid = "1.3.6.1.6.3.15.1.1.5.0"
	usmStatsDecryptionErrors     reportStatusOid = "1.3.6.1.6.3.15.1.1.6.0"
)

func (r reportStatusOid) String() string {
	switch r {
	case snmpUnknownSecurityModels:
		return "SnmpUnknownSecurityModels"
	case snmpInvalidMsgs:
		return "SnmpInvalidMsgs"
	case snmpUnknownPDUHandlers:
		return "SnmpUnknownPDUHandlers"
	case snmpUnavailableContexts:
		return "SnmpUnavailableContexts"
	case snmpUnknownContexts:
		return "SnmpUnknownContexts"
	case usmStatsUnsupportedSecLevels:
		return "UsmStatsUnsupportedSecLevels"
	case usmStatsNotInTimeWindows:
		return "UsmStatsNotInTimeWindows"
	case usmStatsUnknownUserNames:
		return "UsmStatsUnknownUserNames"
	case usmStatsUnknownEngineIDs:
		return "UsmStatsUnknownEngineIDs"
	case usmStatsWrongDigests:
		return "UsmStatsWrongDigests"
	case usmStatsDecryptionErrors:
		return "UsmStatsDecryptionErrors"
	default:
		return "Unknown"
	}
}

var (
	OidSysUpTime = MustParseOidFromString("1.3.6.1.2.1.1.3.0")
	OidSnmpTrap  = MustParseOidFromString("1.3.6.1.6.3.1.1.4.1.0")
)
