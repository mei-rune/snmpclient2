package snmpclient2

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"strings"
	"unicode"
)

var empty_line = errors.New("data is empty.")
var more_line = errors.New("more line")
var re = regexp.MustCompile(`(iso|\d)(.\d+)*\s=\s.*`)

func ParseString(ss []string, is_end bool, vs string) (Variable, []string, error) {
	simple_line := strings.TrimSpace(vs)
	if !strings.HasPrefix(simple_line, "\"") {
		return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, \"" + simple_line + "\" is not start with \".")
	}
	if 1 < len(simple_line) {
		if strings.HasSuffix(simple_line, "\"") && !strings.HasSuffix(simple_line, "\\\"") {
			return NewOctetString([]byte(simple_line[1 : len(simple_line)-1])), ss[1:], nil
		}
	}

	p := -1
	for idx, sss := range ss[1:] {
		if re.MatchString(sss) {
			p = idx
			break
		} else if strings.Contains(sss, "MIB search path") ||
			//strings.HasPrefix(sss, "#") ||
			strings.HasPrefix(sss, "Cannot find module") ||
			strings.HasPrefix(sss, "#tools\\snmpwalk.exe") ||
			strings.HasPrefix(sss, "No log handling enabled") ||
			strings.HasPrefix(sss, "Timeout: No Response from") ||
			strings.Contains(sss, "# ====") {
			p = idx
			break
		}
	}

	if -1 == p {
		if is_end {
			simple_line = strings.TrimLeftFunc(vs, unicode.IsSpace)
			if 1 != len(ss) {
				simple_line = simple_line[1:] + "\r\n" + strings.Join(ss[1:], "\r\n")
			}
			if strings.HasSuffix(simple_line, "\"") && !strings.HasSuffix(simple_line, "\\\"") {
				simple_line = simple_line[:len(simple_line)-1]
			}
			if strings.HasPrefix(simple_line, "\"") {
				simple_line = simple_line[1:]
			}
			return NewOctetString([]byte(simple_line)), nil, nil
		}
		return nil, ss, more_line
	}
	p += 1

	simple_line = strings.TrimLeftFunc(vs, unicode.IsSpace)
	if 1 != p {
		simple_line = simple_line + "\r\n" + strings.Join(ss[1:p], "\r\n")
	}
	if strings.HasSuffix(simple_line, "\"") && !strings.HasSuffix(simple_line, "\\\"") {
		simple_line = simple_line[:len(simple_line)-1]
	}

	if strings.HasPrefix(simple_line, "\"") {
		simple_line = simple_line[1:]
	}

	return NewOctetString([]byte(simple_line)), ss[p:], nil
}

func ReadHex(buf *bytes.Buffer, s string) error {
	for _, h := range strings.Fields(strings.TrimSpace(s)) {
		if 2 != len(h) {
			return errors.New("decode \"" + s + "\" failed, 'len of " + h + "' is not equals 2.")
		}

		b, e := hex.DecodeString(h)
		if nil != e {
			return errors.New("decode \"" + h + "\" \"" + s + "\" failed, " + e.Error())
		}
		buf.Write(b)
	}
	return nil
}

func isHex(s string) bool {
	bs := []byte(s)
	for len(bs) > 0 {
		for unicode.IsSpace(rune(bs[0])) {
			bs = bs[1:]

			if len(bs) == 0 {
				break
			}
		}
		if len(bs) == 0 {
			break
		}
		if len(bs) < 1 {
			break
		}

		if !unicode.IsDigit(rune(bs[0])) &&
			(bs[0] < 'a' || bs[0] > 'f') &&
			(bs[0] < 'A' || bs[0] > 'F') {
			return false
		}
		if !unicode.IsDigit(rune(bs[1])) &&
			(bs[1] < 'a' || bs[1] > 'f') &&
			(bs[1] < 'A' || bs[1] > 'F') {
			return false
		}

		bs = bs[2:]
	}

	return true
}

func ParseHexString(ss []string, is_end bool, vs string) (Variable, []string, error) {
	p := -1
	for idx, sss := range ss[1:] {
		if isHex(sss) {
			// 提高性能用的
			continue
		}

		if strings.HasPrefix(sss, "1.3.6") {
			// 提高性能用的
			p = idx
			break
		} else if strings.HasPrefix(sss, "iso.3.6") {
			// 提高性能用的
			p = idx
			break
		} else if re.MatchString(sss) {
			p = idx
			break
		} else if strings.HasPrefix(sss, "#") ||
			strings.Contains(sss, "MIB search path") ||
			strings.Contains(sss, "Cannot find module") ||
			strings.Contains(sss, "#tools\\snmpwalk.exe") ||
			strings.HasPrefix(sss, "Timeout: No Response from") ||
			strings.HasPrefix(sss, "No log handling enabled") ||
			strings.Contains(sss, "# ====") {
			p = idx
			break
		}
	}

	if -1 == p {
		if is_end {
			var buf bytes.Buffer
			if e := ReadHex(&buf, strings.TrimSpace(vs)); nil != e {
				return nil, nil, errors.New("1parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
			}
			for _, s := range ss[1:] {
				if e := ReadHex(&buf, s); nil != e {
					return nil, nil, errors.New("2parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
				}
			}
			return NewOctetString(buf.Bytes()), nil, nil
		}
		return nil, ss, more_line
	}
	p += 1

	var buf bytes.Buffer
	if e := ReadHex(&buf, strings.TrimSpace(vs)); nil != e {
		return nil, nil, errors.New("3parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
	}
	for _, s := range ss[1:p] {
		if strings.HasPrefix(s, "#") {
			return NewOctetString(buf.Bytes()), ss[p:], nil
		}
		if e := ReadHex(&buf, s); nil != e {
			return nil, nil, errors.New("4parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
		}
	}
	return NewOctetString(buf.Bytes()), ss[p:], nil
}

func ParseLine(ss []string, is_end bool) (*Oid, Variable, []string, error) {
	// fmt.Println("=====================================")
	// fmt.Println(strings.Join(ss, "\r\n"))
	// fmt.Println(is_end)
	// fmt.Println("-------------------------------------")

	if nil == ss || 0 == len(ss) {
		return nil, nil, nil, errors.New("data is nil or empty.")
	}
	for 0 != len(ss) {
		if "" != ss[0] &&
			"End of MIB" != ss[0] &&
			'#' != ss[0][0] {
			break
		}

		ss = ss[1:]
	}
	if nil == ss || 0 == len(ss) {
		return nil, nil, nil, empty_line
	}
	sa := strings.SplitN(ss[0], "=", 2)
	if 2 != len(sa) {
		if strings.Contains(ss[0], "MIB search path") ||
			strings.Contains(ss[0], "Cannot find module") ||
			strings.HasPrefix(ss[0], "Timeout: No Response from") {
			return nil, nil, nil, empty_line
		}
		return nil, nil, nil, empty_line
		//MIB search path: c:/usr/share/snmp/mibs
		//Cannot find module (abc): At line 0 in (none)
		// return nil, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, first line is not \"x = y\".")
	}
	if strings.Contains(ss[0], "# ====") {
		return nil, nil, nil, empty_line
	}
	if strings.Contains(ss[0], "#exit") {
		return nil, nil, nil, empty_line
	}

	oid_str := strings.Replace(sa[0], "iso", "1", 1)
	if strings.HasPrefix(oid_str, "so.") {
		oid_str = "1." + strings.TrimPrefix(oid_str, "so.")
	}
	if strings.HasPrefix(oid_str, "o.") {
		oid_str = "1." + strings.TrimPrefix(oid_str, "o.")
	}
	oid_str = strings.Trim(oid_str, ".")
	oid_str = strings.TrimSpace(oid_str)
	oid, e := ParseOidFromString(oid_str)
	if nil != e {
		return nil, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
	}

	tv := strings.SplitN(sa[1], ":", 2)
	if 2 != len(tv) {
		// iso.3.6.1.4.1.6339.100.7.1.1.7.1 = ""
		simple_line := strings.TrimSpace(sa[1])
		if 1 == len(ss) {
			if strings.HasPrefix(simple_line, "\"") &&
				strings.HasSuffix(simple_line, "\"") {
				simple_line = strings.TrimPrefix(simple_line, "\"")
				simple_line = strings.TrimSuffix(simple_line, "\"")
				v, e := NewOctetStringFromString(simple_line)
				return &oid, v, nil, e
			}
		}
		return &oid, NewOctetString([]byte(simple_line)), ss[1:], nil
		//return oid, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, first line is not \"x = t: y\".")
	}
	t := strings.TrimSpace(tv[0])
	var v Variable
	//var remain []string

	if "Opaque" == t {
		tv = strings.SplitN(tv[1], ":", 2)
		if 2 == len(tv) && "Float" == strings.TrimSpace(tv[0]) {
			return &oid, NewOctetString(bytes.TrimSpace([]byte(tv[1]))), nil, nil
		}

		v, rr, e := ParseString(ss, is_end, tv[1])
		return &oid, v, rr, e
	} else if "STRING" == t {
		v, rr, e := ParseString(ss, is_end, tv[1])
		return &oid, v, rr, e
	} else if "Hex-STRING" == t {
		v, rr, e := ParseHexString(ss, is_end, tv[1])
		return &oid, v, rr, e
		//Hex-STRING: 00 22 93 5D EF 00
		// iso.3.6.1.2.1.14.4.1.8.0.0.0.0.1.34.2.28.4.34.2.28.4 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
		// DE E4 00 3C 00 00 00 03 22 02 1C 04 FF FF FF FF
		// 03 00 00 01 22 02 00 01 22 03 1C 1A 01 00 01 E8
		// 22 03 1C 19 FF FF FF FF 03 00 01 E8
	} else {
		if 1 != len(ss) {
			return &Oid{}, nil, nil, errors.New("parse `" +
				strings.Join(ss, "\r\n") + "` failed, it is not muti line.")
		}

		switch t {
		case "OID":
			v, e = NewOidFromString(strings.TrimSpace(strings.Replace(tv[1], "iso", "1", 1)))
		case "INTEGER":
			if strings.TrimSpace(tv[1]) == "" {
				v = NewInteger(0)
				break
			}
			v, e = NewIntegerFromString(strings.TrimSpace(tv[1]))
		case "Gauge32":
			v, e = NewGauge32FromString(strings.TrimSpace(tv[1]))
		case "Counter32":
			v, e = NewCounter32FromString(strings.TrimSpace(tv[1]))
		case "Counter64":
			v, e = NewCounter64FromString(strings.TrimSpace(tv[1]))
		case "Timeticks":
			//Timeticks: (16465600) 1 day, 21:44:16.00
			p1 := strings.IndexRune(tv[1], '(')
			if -1 == p1 {
				return &Oid{}, nil, nil, errors.New("parse `" +
					strings.Join(ss, "\r\n") + "` failed, '" + tv[1] + "' is syntex error.")
			}

			p2 := strings.IndexRune(tv[1], ')')
			if -1 == p2 || p1 > p2 {
				return &Oid{}, nil, nil, errors.New("parse `" +
					strings.Join(ss, "\r\n") + "` failed, '" + tv[1] + "' is syntex error.")
			}
			v, e = NewTimeticksFromString(strings.TrimSpace(tv[1][p1+1 : p2]))
		case "IpAddress":
			v, e = NewIPAddressFromString(strings.TrimSpace(tv[1]))
		default:
			return &Oid{}, nil, nil, errors.New("parse `" +
				strings.Join(ss, "\r\n") + "` failed, it is not supported - " + t)
		}
	}
	return &oid, v, nil, e
}

func Read(reader io.Reader, cb func(oid Oid, value Variable) error) error {
	rd := textproto.NewReader(bufio.NewReader(reader))
	var line string
	var s []string
	var e error
	for {
		line, e = rd.ReadLine()
		if io.EOF == e {
			for nil != s {
				oid, value, remain, e := ParseLine(append(s, line), true)
				if nil != e {
					if empty_line == e {
						s = remain
						continue
					}
					// return e
					fmt.Println(e)

					s = remain
					continue
				}

				if e = cb(*oid, value); nil != e {
					return e
				}
				if nil == remain || 0 == len(remain) {
					s = nil
				} else {
					s = remain
				}
			}
			break
		}

		if nil != e {
			return e
		}
		s = append(s, line)
	retry:
		oid, value, remain, e := ParseLine(s, false)
		if nil != e {
			if more_line == e {
				continue
			}
			if empty_line == e {
				s = remain
				continue
			}

			//return e
			fmt.Println(e)

			s = remain
			continue
		}

		if e = cb(*oid, value); nil != e {
			return e
		}

		if nil != remain && len(s) == len(remain) {
			panic("dead parse")
		}
		if nil != remain && 0 != len(remain) {
			s = remain
			goto retry
		}

		s = nil
	}
	return nil
}
