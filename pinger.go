package snmpclient2

import (
	"encoding/asn1"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PingResult struct {
	Id             int
	Addr           net.Addr
	Version        SnmpVersion
	Community      string
	SecurityParams map[string]string
	Error          error
	Timestamp      time.Time
}

type internal_pinger struct {
	network        string
	id             int
	version        SnmpVersion
	community      string
	securityParams map[string]string
	conn           net.PacketConn
	wait           *sync.WaitGroup
	ch             chan *PingResult
	is_running     int32
	cached_bytes   []byte
	mpv1           Security
	mpv3           Security
}

// make(chan *PingResult, capacity)
func newPinger(network, laddr string, wait *sync.WaitGroup, ch chan *PingResult, version SnmpVersion, community string,
	securityParams map[string]string) (*internal_pinger, error) {
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("ListenPacket(%q, %q) failed: %v", network, laddr, err)
	}
	internal_pinger := &internal_pinger{network: network,
		id:             1,
		wait:           wait,
		conn:           c,
		ch:             ch,
		version:        version,
		community:      community,
		securityParams: securityParams,
		is_running:     1,
		mpv1:           NewCommunity(),
		mpv3:           NewUsm()}

	go internal_pinger.serve()
	internal_pinger.wait.Add(1)
	return internal_pinger, nil
}

// func Newpinger(network, laddr string, ch chan *PingResult, version SnmpVersion, community string) (*internal_pinger, error) {
// 	return newpinger(network, laddr, ch, version, community, nil)
// }

// func NewV3pinger(network, laddr string, ch chan *PingResult, securityParams map[string]string) (*internal_pinger, error) {
// 	return newpinger(network, laddr, ch, SNMP_V3, "", securityParams)
// }

func (self *internal_pinger) closeIO() {
	atomic.StoreInt32(&self.is_running, 0)
	self.conn.Close()
}

func (self *internal_pinger) Close() {
	self.closeIO()
	self.wait.Wait()
	close(self.ch)
}

func (self *internal_pinger) GetChannel() <-chan *PingResult {
	return self.ch
}

var emptyParams = map[string]string{}

func (self *internal_pinger) Send(raddr string) error {
	ra, err := net.ResolveUDPAddr(self.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.network, raddr, err)
	}
	return self.SendPdu(0, ra, self.version, self.community, self.securityParams)
}

func (self *internal_pinger) SendPdu(id int, ra *net.UDPAddr, version SnmpVersion, community string, securityParams map[string]string) error {
	// start_at := time.Now()
	// var send_elapsed time.Duration = 0
	// defer func() {
	// 	interval := time.Now().Sub(start_at)
	// 	if interval > 10*time.Millisecond {
	// 		log.Println("[snmp-ping] send to", ra.String(), " elapsed ", interval, send_elapsed)
	// 	}
	// }()
	if 0 == id {
		self.id++
		id = self.id
	}

	var msg Message = nil
	switch version {
	case V1, V2c:
		//requestId: id, community: community
		pdu := NewPduWithOids(version, GetRequest, []Oid{Oid{Value: []int{1, 3, 6, 1, 2, 1, 1, 2, 0}}})
		pdu.SetRequestId(id)
		m := &MessageV1{
			version: version,
			pdu:     pdu,
		}
		m.Community = []byte(community)

		b, err := m.PDU().Marshal()
		if err != nil {
			return err
		}
		m.SetPduBytes(b)
		msg = m
	case V3:
		//pdu = &V3PDU{op: GetRequest, requestId: id, identifier: id,
		//	securityModel: &USM{auth_proto: SNMP_AUTH_NOAUTH, priv_proto: SNMP_PRIV_NOPRIV}}
		pdu := NewPdu(version, GetRequest)
		pdu.SetRequestId(id)
		msg = NewMessage(version, pdu)
		m := msg.(*MessageV3)
		m.globalDataV3.initFlags()
		m.globalDataV3.MessageId = id
		m.globalDataV3.SecurityModel = securityUsm
		b, err := m.PDU().Marshal()
		if err != nil {
			return err
		}
		m.SetPduBytes(b)
	default:
		return fmt.Errorf("Unsupported version - %v", version)
	}

	// if nil == self.cached_bytes {
	// 	self.cached_bytes = make([]byte, 1024)
	// }

	bytes, e := msg.Marshal()
	if e != nil {
		return fmt.Errorf("EncodePDU failed: %v", e)
	}

	//before_at := time.Now()
	l, err := self.conn.WriteTo(bytes, ra)
	//send_elapsed = time.Now().Sub(before_at)
	if err != nil {
		return fmt.Errorf("WriteTo failed: %v", err)
	}
	if l == 0 {
		return fmt.Errorf("WriteTo failed: wlen == 0")
	}
	return nil
}

func (self *internal_pinger) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	select {
	case res := <-self.ch:
		return res.Addr, res.Version, res.Error
	case <-time.After(timeout):
		return nil, 0, TimeoutError
	}
	return nil, 0, TimeoutError
}

func (self *internal_pinger) serve() {
	defer self.wait.Done()

	cached := make([]byte, 4000)

	for 1 == atomic.LoadInt32(&self.is_running) {
		l, ra, err := self.conn.ReadFrom(cached)
		if err != nil {
			if strings.Contains(err.Error(), "No service is operating") { //Port Unreachable
				continue
			}
			if strings.Contains(err.Error(), "forcibly closed by the remote host") { //Port Unreachable
				continue
			}
			self.ch <- &PingResult{Error: fmt.Errorf("ReadFrom failed: %v, %v", ra, err)}
			continue
		}
		recv_bytes := cached[:l]

		var raw asn1.RawValue
		if _, err = asn1.Unmarshal(recv_bytes, &raw); err != nil {
			log.Printf("[snmp-pinger] Invalid Message object - %s : [%s]",
				err.Error(), ToHexStr(recv_bytes, " "))
			continue
		}

		if raw.Class != ClassUniversal || raw.Tag != SYNTAX_SEQUENCE || !raw.IsCompound {
			log.Printf("[snmp-pinger] Invalid Message object - Class [%02x], Tag [%02x] : [%s]",
				raw.FullBytes[0], raw.Tag, ToHexStr(recv_bytes, " "))
			continue
		}

		next := raw.Bytes
		var version int
		next, err = asn1.Unmarshal(next, &version)
		if err != nil {
			log.Printf("[snmp-pinger] Invalid Message object - %s : [%s]",
				err.Error(), ToHexStr(recv_bytes, " "))
			continue
		}

		if SnmpVersion(version) == V3 {
			var managedId int
			next, err = asn1.Unmarshal(next, &managedId)
			if err != nil {
				log.Printf("[snmp-pinger] Failed to Unmarshal message - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				continue
			}

			self.ch <- &PingResult{Id: managedId, Addr: ra, Version: SnmpVersion(version), Timestamp: time.Now()}
		} else {
			pdu := &PduV1{}
			recvMsg := &MessageV1{
				version: SnmpVersion(version),
				pdu:     pdu,
			}
			_, err = recvMsg.Unmarshal(recv_bytes)
			if err != nil {
				log.Printf("[snmp-pinger] Failed to Unmarshal message - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				continue
			}

			_, err = pdu.Unmarshal(recvMsg.PduBytes())
			if err != nil {
				log.Printf("[snmp-pinger] Failed to Unmarshal PDU - %s : [%s]",
					err.Error(), ToHexStr(recv_bytes, " "))
				continue
			}
			self.ch <- &PingResult{Id: pdu.RequestId(),
				Addr:      ra,
				Version:   SnmpVersion(version),
				Community: string(recvMsg.Community),
				Timestamp: time.Now()}
		}

	}
}

type Pingers struct {
	internals []*internal_pinger
	ch        chan *PingResult
	wait      sync.WaitGroup
}

func NewPingers(capacity int) *Pingers {
	return &Pingers{internals: make([]*internal_pinger, 0, 10), ch: make(chan *PingResult, capacity)}
}

func (self *Pingers) Listen(network, laddr string, version SnmpVersion, community string) error {
	p, e := newPinger(network, laddr, &self.wait, self.ch, version, community, nil)
	if nil != e {
		return e
	}
	self.internals = append(self.internals, p)
	return nil
}

func (self *Pingers) ListenV3(network, laddr string, securityParams map[string]string) error {
	p, e := newPinger(network, laddr, &self.wait, self.ch, V3, "", securityParams)
	if nil != e {
		return e
	}
	self.internals = append(self.internals, p)
	return nil
}

func (self *Pingers) Close() {
	for _, p := range self.internals {
		p.closeIO()
	}
	self.wait.Wait()
	close(self.ch)
}

func (self *Pingers) GetChannel() <-chan *PingResult {
	return self.ch
}

func (self *Pingers) Length() int {
	return len(self.internals)
}

func (self *Pingers) Send(idx int, raddr string) error {
	return self.internals[idx].Send(raddr)
}

func (self *Pingers) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	timer := time.NewTimer(timeout)
	select {
	case res := <-self.ch:
		timer.Stop()
		return res.Addr, res.Version, res.Error
	case <-timer.C:
		return nil, 0, TimeoutError
	}
	return nil, 0, TimeoutError
}

type Pinger struct {
	internal *internal_pinger
	ch       chan *PingResult
	wait     sync.WaitGroup
}

func NewPinger(network, laddr string, capacity int) (*Pinger, error) {
	self := &Pinger{}
	self.ch = make(chan *PingResult, capacity)
	p, e := newPinger(network, laddr, &self.wait, self.ch, V2c, "public", emptyParams)
	if nil != e {
		return nil, e
	}
	self.internal = p
	return self, nil
}

func (self *Pinger) Close() {
	if nil == self {
		return
	}
	if nil != self.internal {
		self.internal.closeIO()
		self.wait.Wait()
		close(self.ch)
	}
}

func (self *Pinger) GetChannel() <-chan *PingResult {
	return self.ch
}

func (self *Pinger) SendPdu(id int, ra *net.UDPAddr, version SnmpVersion, community string) error {
	return self.internal.SendPdu(id, ra, version, community, nil)
}

func (self *Pinger) Send(id int, raddr string, version SnmpVersion, community string) error {
	ra, err := net.ResolveUDPAddr(self.internal.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.internal.network, raddr, err)
	}

	return self.internal.SendPdu(id, ra, version, community, nil)
}

func (self *Pinger) SendV3(id int, raddr string, securityParams map[string]string) error {
	ra, err := net.ResolveUDPAddr(self.internal.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.internal.network, raddr, err)
	}

	return self.internal.SendPdu(id, ra, V3, "", securityParams)
}

func (self *Pinger) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	select {
	case res := <-self.ch:
		return res.Addr, res.Version, res.Error
	case <-time.After(timeout):
		return nil, 0, TimeoutError
	}
	return nil, 0, TimeoutError
}
