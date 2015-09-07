package snmpclient2

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

type OidAndValue struct {
	Oid   Oid
	Value Variable
}

func compareOidAdValue(a1, b1 Item) int {
	a, ok := a1.(Oid)
	if !ok {
		v, ok := a1.(*OidAndValue)
		if !ok {
			panic("a1 is not OidAndValue")
		}
		a = v.Oid
	}

	b, ok := b1.(Oid)
	if !ok {
		v, ok := b1.(*OidAndValue)
		if !ok {
			panic("b1 is not OidAndValue")
		}
		b = v.Oid
	}

	a_uint32s := a.Value
	b_uint32s := b.Value
	for idx, c := range a_uint32s {
		if idx >= len(b_uint32s) {
			return 1
		}
		if c == b_uint32s[idx] {
			continue
		}

		if c < b_uint32s[idx] {
			return -1
		}
		return 1
	}
	if len(a_uint32s) == len(b_uint32s) {
		return 0
	}
	return -1
}

func convertOid(a interface{}) *Oid {
	o, ok := a.(Oid)
	if ok {
		return &o
	}
	v, ok := a.(*OidAndValue)
	if ok {
		return &v.Oid
	}
	panic("a1 is not OidAndValue")
}

func compareOidAdValueWith(a1, b1 Item) int {
	r := compareOidAdValue(a1, b1)
	if r > 0 {
		fmt.Println(convertOid(a1).String() + ">" + convertOid(b1).String())
	} else if r < 0 {
		fmt.Println(convertOid(a1).String() + "<" + convertOid(b1).String())
	} else {
		fmt.Println(convertOid(a1).String() + "==" + convertOid(b1).String())
	}

	return r
}

func NewMibTree() *Tree {
	return NewTree(compareOidAdValue)
}

// ******************************************
//  It is for test.
type UdpServer struct {
	name       string
	origin     string
	conn       net.PacketConn
	listenAddr net.Addr
	waitGroup  sync.WaitGroup
	mpv1       Security
	//priv_type  PrivType
	//priv_key []byte

	return_error_if_oid_not_exists bool
	is_update_mibs                 bool
	mibs                           *Tree
}

func NewUdpServerFromFile(nm, addr, file string, is_update_mibs bool) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin:         addr,
		is_update_mibs: is_update_mibs,
		mibs:           NewMibTree(),
		mpv1:           NewCommunity()}
	r, e := os.Open(file)
	if nil != e {
		return nil, e
	}
	if e := Read(r, func(oid Oid, value Variable) error {
		if ok := srv.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {
			if srv.is_update_mibs {
				if ok = srv.mibs.DeleteWithKey(oid); !ok {
					return errors.New("insert '" + oid.String() + "' failed, delete failed.")
				}
				if ok = srv.mibs.Insert(&OidAndValue{Oid: oid,
					Value: value}); !ok {
					return errors.New("insert '" + oid.String() + "' failed.")
				}
			} else {
				return errors.New("insert '" + oid.String() + "' failed.")
			}
		}
		return nil
	}); nil != e {
		return nil, e
	}
	return srv, srv.start()
}

func NewUdpServerFromString(nm, addr, mibs string, is_update_mibs bool) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin:         addr,
		is_update_mibs: is_update_mibs,
		mibs:           NewMibTree(),
		mpv1:           NewCommunity()}
	if e := Read(bytes.NewReader([]byte(mibs)), func(oid Oid, value Variable) error {
		if ok := srv.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {

			if srv.is_update_mibs {
				if ok = srv.mibs.DeleteWithKey(oid); !ok {
					return errors.New("insert '" + oid.String() + "' failed, delete failed.")
				}
				if ok = srv.mibs.Insert(&OidAndValue{Oid: oid,
					Value: value}); !ok {
					return errors.New("insert '" + oid.String() + "' failed.")
				}
			} else {
				return errors.New("insert '" + oid.String() + "' failed.")
			}
		}
		return nil
	}); nil != e {
		return nil, e
	}
	return srv, srv.start()
}

func (self *UdpServer) ReturnErrorIfOidNotExists(status bool) *UdpServer {
	self.return_error_if_oid_not_exists = status
	return self
}

func (self *UdpServer) ReloadMibsFromString(mibs string) error {
	self.mibs = NewMibTree()
	return self.LoadMibsFromString(mibs)
}

func (self *UdpServer) LoadFile(file string) error {
	mibs, e := ioutil.ReadFile(file)
	if nil != e {
		return e
	}
	return self.LoadMibsFromString(string(mibs))
}

func (self *UdpServer) LoadMibsFromString(mibs string) error {
	if e := Read(bytes.NewReader([]byte(mibs)), func(oid Oid, value Variable) error {
		if ok := self.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {

			if self.is_update_mibs {
				if ok = self.mibs.DeleteWithKey(oid); !ok {
					return errors.New("insert '" + oid.String() + "' failed, delete failed.")
				}
				if ok = self.mibs.Insert(&OidAndValue{Oid: oid,
					Value: value}); !ok {
					return errors.New("insert '" + oid.String() + "' failed.")
				}
			} else {
				return errors.New("insert '" + oid.String() + "' failed.")
			}
		}
		return nil
	}); nil != e {
		return e
	}
	return nil
}
func (self *UdpServer) GetPort() string {
	s := self.listenAddr.String()
	if i := strings.LastIndex(s, ":"); -1 != i {
		return s[i+1:]
	}
	return ""
}

func (self *UdpServer) Close() {
	self.conn.Close()
	self.waitGroup.Wait()
}

func (self *UdpServer) start() error {
	var conn net.PacketConn
	var e error

	if nil == self.listenAddr {
		conn, e = net.ListenPacket("udp", self.origin)
	} else {
		conn, e = net.ListenPacket("udp", self.listenAddr.String())
	}
	if nil != e {
		return e
	}

	self.conn = conn
	self.listenAddr = conn.LocalAddr()

	self.waitGroup.Add(1)
	go self.serve()

	return nil
}

func (self *UdpServer) serve() {
	defer func() {
		self.conn = nil
		self.waitGroup.Done()
	}()

	var cached_bytes [10240]byte

	for {
		n, addr, err := self.conn.ReadFrom(cached_bytes[:])
		if nil != err {
			log.Println("[", self.name, "]", err.Error())
			break
		}

		func(recv_bytes []byte) {
			var raw asn1.RawValue
			_, err = asn1.Unmarshal(recv_bytes, &raw)
			if err != nil {
				log.Printf("["+self.name+"]Invalid MessageV3 object - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				return
			}

			if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
				log.Printf("["+self.name+"]Invalid MessageV3 object - Class [%02x], Tag [%02x] : [%s]",
					raw.FullBytes[0], raw.Tag, ToHexStr(recv_bytes, " "))
				return
			}
			next := raw.Bytes

			var version int
			next, err = asn1.Unmarshal(next, &version)
			if err != nil {
				log.Printf("["+self.name+"]Invalid MessageV3 object - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				return
			}

			if SnmpVersion(version) == V3 {
				// var managedId int
				// next, err = asn1.Unmarshal(next, &managedId)
				// if err != nil {
				// 	return
				// }

				// pdu := &ScopedPdu{}
				// recvMsg := NewMessage(SnmpVersion(version), pdu)
				// _, err = recvMsg.Unmarshal(recv_bytes)
				// if err != nil {
				// 	log.Printf(client.logCtx, "Failed to Unmarshal message - %s : [%s]",
				// 		err.Error(), ToHexStr(recv_bytes, " "))
				// 	return
				// }

				// var ok bool
				// request, ok = client.pendings[managedId]
				// if !ok {
				// 	log.Printf(client.logCtx, "request with requestId was", managedId, "is not exists.")
				// 	return
				// }
				// delete(client.pendings, managedId)
				// request.response = pdu

				// err = client.mpv3.ProcessIncomingMessage(snmp, nil, recvMsg)
				// if err != nil {
				// 	log.Printf(client.logCtx, "Failed to process incoming message - %s : [%s]",
				// 		err.Error(), ToHexStr(recv_bytes, " "))
				// 	return
				// }

				log.Printf("["+self.name+"]Failed to process incoming message - v3 message is unsupported : [%s]",
					ToHexStr(recv_bytes, " "))
				return
			} else {
				recvMsg := &MessageV1{
					version: SnmpVersion(version),
					pdu:     &PduV1{},
				}
				_, err = recvMsg.Unmarshal(recv_bytes)
				if err != nil {
					log.Printf("["+self.name+"]Failed to Unmarshal message - %s : [%s]",
						err.Error(), ToHexStr(recv_bytes, " "))
					return
				}

				err = self.mpv1.ProcessIncomingMessage(nil, recvMsg)
				if err != nil {
					log.Printf("["+self.name+"]Failed to process incoming message - %s : [%s]",
						err.Error(), ToHexStr(recv_bytes, " "))
					return
				}
				self.on_v2(addr, recvMsg, recv_bytes)
			}
		}(cached_bytes[:n])
	}
}

func (self *UdpServer) on_v2(addr net.Addr, p *MessageV1, cached_bytes []byte) {
	pdu := &PduV1{
		pduType:   GetResponse,
		requestId: p.PDU().RequestId(),
	}

	res := &MessageV1{
		version: p.Version(),
		pdu:     pdu,
	}
	//res.SetMaxMsgSize(p.GetMaxMsgSize())

	switch p.PDU().PduType() {
	case GetRequest:
		for _, vb := range p.PDU().VariableBindings() {
			v := self.GetValueByOid(vb.Oid)
			if nil == v {
				if self.return_error_if_oid_not_exists {
					pdu.SetErrorStatus(NoSuchName)
					break
				}
				continue
			}
			res.PDU().AppendVariableBinding(vb.Oid, v)
		}
	case GetNextRequest:
		for _, vb := range p.PDU().VariableBindings() {
			o, v := self.GetNextValueByOid(vb.Oid)
			if nil == v {
				continue
			}
			res.PDU().AppendVariableBinding(*o, v)
		}
	default:
		log.Println("[", self.name, "] snmp type is not supported.")
	}

	s, err := res.Marshal()
	if err != nil {
		return
	}
	if _, e := self.conn.WriteTo(s, addr); nil != e {
		log.Println("[warn]", e)
		return
	}
}

func (self *UdpServer) GetValueByOid(oid Oid) Variable {
	if v := self.mibs.Get(oid); nil != v {
		if sv, ok := v.(*OidAndValue); ok {
			return sv.Value
		}
		panic(fmt.Sprintf("it is not a Variable - [%T]%v", v, v))
	}
	return nil
}

func (self *UdpServer) GetNextValueByOid(oid Oid) (*Oid, Variable) {
	it := self.mibs.FindGE(oid)
	if it.Limit() {
		return nil, nil
	}
	v := it.Item()
	if nil == v {
		return nil, nil
	}
	sv, ok := v.(*OidAndValue)
	if !ok {
		panic(fmt.Sprintf("it is not a Variable - [%T]%v", v, v))
	}

	if 0 != compareOidAdValue(oid, sv.Oid) {
		return &sv.Oid, sv.Value
	}
	it = it.Next()
	if it.Limit() {
		return nil, nil
	}
	v = it.Item()
	if nil == v {
		return nil, nil
	}
	sv, ok = v.(*OidAndValue)
	if ok {
		return &sv.Oid, sv.Value
	}
	panic(fmt.Sprintf("it is not a Variable - [%T]%v", v, v))
}