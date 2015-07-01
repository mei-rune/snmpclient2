package snmpclient2

import (
	"strconv"
	"time"
)

type SNMPVersion int

const (
	V1  SNMPVersion = 0
	V2c SNMPVersion = 1
	V3  SNMPVersion = 3
)

func (s SNMPVersion) String() string {
	switch s {
	case V1:
		return "1"
	case V2c:
		return "2c"
	case V3:
		return "3"
	default:
		return "Unknown"
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

type SecurityLevel int

const (
	NoAuthNoPriv SecurityLevel = iota
	AuthNoPriv
	AuthPriv
)

func (s SecurityLevel) String() string {
	switch s {
	case NoAuthNoPriv:
		return "NoAuthNoPriv"
	case AuthNoPriv:
		return "AuthNoPriv"
	case AuthPriv:
		return "AuthPriv"
	default:
		return "Unknown"
	}
}

type AuthProtocol string

const (
	Md5 AuthProtocol = "MD5"
	Sha AuthProtocol = "SHA"
)

type PrivProtocol string

const (
	Des PrivProtocol = "DES"
	Aes PrivProtocol = "AES"
)

const (
	timeoutDefault = 5 * time.Second
	recvBufferSize = 1 << 11
	msgSizeDefault = 1400
	msgSizeMinimum = 484
	tagMask        = 0x1f
	mega           = 1 << 20
)

// ASN.1 Class
const (
	ClassUniversal = iota
	ClassApplication
	ClassContextSpecific
	ClassPrivate
)

// ASN.1 Tag
const (
	SYNTAX_INTEGER        = 0x02
	SYNTAX_OCTETSTRING    = 0x04
	SYNTAX_NULL           = 0x05
	SYNTAX_OID            = 0x06
	SYNTAX_SEQUENCE       = 0x10
	SYNTAX_IPADDRESS      = 0x40
	SYNTAX_COUNTER32      = 0x41
	SYNTAX_GAUGE32        = 0x42
	SYNTAX_TIMETICKS      = 0x43
	SYNTAX_OPAQUE         = 0x44
	SYNTAX_COUNTER64      = 0x46
	SYNTAX_NOSUCHOBJECT   = 0x80
	SYNTAX_NOSUCHINSTANCE = 0x81
	SYNTAX_ENDOFMIBVIEW   = 0x82
)

func ToSyntexString(t int) string {
	switch t {
	case SYNTAX_INTEGER:
		return "int"
	case SYNTAX_OCTETSTRING:
		return "octets"
	case SYNTAX_NULL:
		return "null"
	case SYNTAX_OID:
		return "oid"
	case SYNTAX_SEQUENCE:
		return "sequence"
	case SYNTAX_IPADDRESS:
		return "ip"
	case SYNTAX_COUNTER32:
		return "counter32"
	case SYNTAX_GAUGE32:
		return "gauge32"
	case SYNTAX_TIMETICKS:
		return "timeticks"
	case SYNTAX_OPAQUE:
		return "opaque"
	case SYNTAX_COUNTER64:
		return "counter64"
	case SYNTAX_NOSUCHOBJECT:
		return "NOSUCHOBJECT"
	case SYNTAX_NOSUCHINSTANCE:
		return "NOSUCHINSTANCE"
	case SYNTAX_ENDOFMIBVIEW:
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
	OidSysUpTime = MustNewOid("1.3.6.1.2.1.1.3.0")
	OidSnmpTrap  = MustNewOid("1.3.6.1.6.3.1.1.4.1.0")
)
