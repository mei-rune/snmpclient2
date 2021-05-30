package snmpclient2

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/runner-mei/snmpclient2/asn1"
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
	miss       int
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
	community                      string
	mibsByEngine                   map[string]*Tree
	mibs                           *Tree
}

func NewUdpServerFromFile(nm, addr, file string, is_update_mibs bool) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin:         addr,
		is_update_mibs: is_update_mibs,
		mibs:           NewMibTree(),
		mibsByEngine:   map[string]*Tree{},
		mpv1:           NewCommunity()}
	if err := srv.LoadFile(file); err != nil {
		return nil, err
	}
	return srv, srv.start()
}

func NewUdpServerFromString(nm, addr, mibs string, is_update_mibs bool) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin:         addr,
		is_update_mibs: is_update_mibs,
		mibs:           NewMibTree(),
		mibsByEngine:   map[string]*Tree{},
		mpv1:           NewCommunity()}
	if e := srv.LoadMibsFromString(mibs); nil != e {
		return nil, e
	}
	return srv, srv.start()
}

func (self *UdpServer) SetCommunity(community string) {
	self.community = community
}

func (self *UdpServer) SetMiss(miss int) {
	self.miss = miss
}

func (self *UdpServer) ReturnErrorIfOidNotExists(status bool) *UdpServer {
	self.return_error_if_oid_not_exists = status
	return self
}

func (self *UdpServer) ReloadMibsFromFile(file string) error {
	return self.LoadFileTo("", file, true)
}

func (self *UdpServer) ReloadMibsFromString(mibs string) error {
	return self.LoadMibsIntoEngine("", bytes.NewReader([]byte(mibs)), true)
}

func (self *UdpServer) LoadFile(file string) error {
	return self.LoadFileTo("", file, false)
}

func (self *UdpServer) LoadFileTo(engineID, filename string, isReset bool) error {
	if strings.HasPrefix(filename, "http://") || strings.HasPrefix(filename, "https://") {
		resp, err := http.Get(filename)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			if resp.Body != nil {
				io.Copy(os.Stdout, resp.Body)
			}
			return errors.New(resp.Status)
		}

		return self.LoadMibsIntoEngine(engineID, resp.Body, isReset)
	}

	ext := filepath.Ext(filename)
	if ext != ".zip" {
		r, err := os.Open(filename)
		if err != nil {
			return err
		}
		return self.LoadMibsIntoEngine(engineID, r, isReset)
	}

	r, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer r.Close()

	if len(r.File) == 0 {
		return errors.New("'" + filename + "' is empty")
	}

	if len(r.File) > 1 {
		for idx := range r.File {
			fmt.Println(r.File[idx].Name)
		}
		return errors.New("'" + filename + "' is muti files")
	}

	rc, err := r.File[0].Open()
	if err != nil {
		return err
	}
	return self.LoadMibsIntoEngine(engineID, rc, isReset)
}

func (self *UdpServer) LoadMibsFromString(mibs string) error {
	return self.LoadMibsIntoEngine("", bytes.NewReader([]byte(mibs)), false)
}

func (self *UdpServer) LoadMibsIntoEngine(engineID string, rd io.Reader, isReset bool) error {
	defer func() {
		if f, ok := rd.(*os.File); ok {
			if f != nil {
				f.Close()
			}
			return
		}

		closer, ok := rd.(io.Closer)
		if ok && closer != nil {
			closer.Close()
		}
	}()

	var mibs *Tree
	if engineID == "" || engineID == self.community {
		if isReset {
			self.mibs = NewMibTree()
		}
		mibs = self.mibs
	} else {
		if self.mibsByEngine == nil {
			self.mibsByEngine = map[string]*Tree{}
		}

		if isReset {
			mibs = NewMibTree()
			self.mibsByEngine[engineID] = mibs
		} else {
			mibs = self.mibsByEngine[engineID]
			if mibs == nil {
				mibs = NewMibTree()
				self.mibsByEngine[engineID] = mibs
			}
		}
	}

	if e := Read(rd, func(oid Oid, value Variable) error {
		if ok := mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {

			if self.is_update_mibs {
				if ok = mibs.DeleteWithKey(oid); !ok {
					return errors.New("insert '" + oid.String() + "' failed, delete failed.")
				}
				if ok = mibs.Insert(&OidAndValue{Oid: oid,
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
	_, port, _ := net.SplitHostPort(s)
	return port
}

func (self *UdpServer) GetIntPort() int {
	port := self.GetPort()
	if port == "" {
		return 0
	}
	i, _ := strconv.Atoi(port)
	return i
}

func (self *UdpServer) Close() error {
	if self.conn != nil {
		self.conn.Close()
		self.waitGroup.Wait()
		self.conn = nil
	}

	return nil
}

func (self *UdpServer) Pause() error {
	self.Close()
	log.Println("udp server is exited - ", self.listenAddr)
	return nil
}

func (self *UdpServer) Resume() error {
	err := self.start()
	if err == nil {
		log.Println("udp server is resumed, listen at", self.listenAddr)
	}
	return err
}

func (self *UdpServer) Restart() error {
	self.Close()

	self.listenAddr = nil
	log.Println("udp server is exited")
	err := self.start()
	if err == nil {
		log.Println("udp server is restarted, listen at", self.listenAddr.String())
	}
	return err
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

	count := 0

	for {
		n, addr, err := self.conn.ReadFrom(cached_bytes[:])
		if nil != err {
			log.Println("[", self.name, "]", err.Error())
			break
		}

		count++

		if self.miss > 1 && count%self.miss == 0 {
			continue
		}

		func(recv_bytes []byte) {
			var raw asn1.RawValue
			_, err = asn1.Unmarshal(recv_bytes, &raw)
			if err != nil {
				log.Printf("["+self.name+"]Invalid MessageV3 object - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				return
			}

			if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
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
			}
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

	var mibs *Tree
	if self.mibsByEngine != nil {
		mibs = self.mibsByEngine[string(p.Community)]
	}
	if mibs == nil {
		if self.community == "" || self.community == string(p.Community) {
			mibs = self.mibs
		} else {
			log.Println("community isnot match")
		}
	}

	if mibs == nil {
		for key := range self.mibsByEngine {
			fmt.Println(key)
		}
		return
	}

	//res.SetMaxMsgSize(p.GetMaxMsgSize())

	switch p.PDU().PduType() {
	case GetRequest:
		for _, vb := range p.PDU().VariableBindings() {

			v := self.GetValueByOid(mibs, vb.Oid)
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
			o, v := self.GetNextValueByOid(mibs, vb.Oid)
			if nil == v {
				continue
			}
			res.PDU().AppendVariableBinding(*o, v)
		}
	default:
		log.Println("[", self.name, "] snmp type is not supported.")
	}

	err := NewCommunity().GenerateRequestMessage(&Arguments{Community: ""}, res)
	if err != nil {
		log.Println("[", self.name, "] failed to generate request,", err)
		return
	}

	s, err := res.Marshal()
	if err != nil {
		log.Println("[", self.name, "] failed to marshal,", err)
		return
	}
	if _, e := self.conn.WriteTo(s, addr); nil != e {
		log.Println("[", self.name, "] failed to write response,", e)
		return
	}
}

func (self *UdpServer) GetValueByOid(mibs *Tree, oid Oid) Variable {
	if v := mibs.Get(oid); nil != v {
		if sv, ok := v.(*OidAndValue); ok {
			return sv.Value
		}
		panic(fmt.Sprintf("it is not a Variable - [%T]%v", v, v))
	}
	return nil
}

func (self *UdpServer) GetNextValueByOid(mibs *Tree, oid Oid) (*Oid, Variable) {
	it := mibs.FindGE(oid)
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
