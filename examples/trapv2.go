package main

import (
	"fmt"

	"github.com/k-sone/snmpgo"
)

func main() {
	snmp, err := snmpgo.NewSNMP(snmpgo.Arguments{
		Version:   snmpgo.V2c,
		Address:   "127.0.0.1:162",
		Retries:   1,
		Community: "public",
	})
	if err != nil {
		// Failed to create snmpgo.SNMP object
		fmt.Println(err)
		return
	}

	// Build VariableBinding list
	var VariableBindings snmpgo.VariableBindings
	VariableBindings = append(VariableBindings, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(1000)))

	oid, _ := snmpgo.ParseOidFromString("1.3.6.1.6.3.1.1.5.3")
	VariableBindings = append(VariableBindings, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, oid))

	oid, _ = snmpgo.ParseOidFromString("1.3.6.1.2.1.2.2.1.1.2")
	VariableBindings = append(VariableBindings, snmpgo.NewVarBind(oid, snmpgo.NewInteger(2)))

	oid, _ = snmpgo.ParseOidFromString("1.3.6.1.2.1.31.1.1.1.1.2")
	VariableBindings = append(VariableBindings, snmpgo.NewVarBind(oid, snmpgo.NewOctetString([]byte("eth0"))))

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		fmt.Println(err)
		return
	}
	defer snmp.Close()

	if err = snmp.V2Trap(VariableBindings); err != nil {
		// Failed to request
		fmt.Println(err)
		return
	}
}
