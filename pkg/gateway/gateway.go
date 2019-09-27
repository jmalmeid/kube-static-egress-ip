package gateway

import (
	"errors"
	"fmt"

	"io/ioutil"
	"os"		
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	ipset "github.com/janeczku/go-ipset/ipset"
)

// EgressGateway configures the gateway node (based on the `staticegressip` CRD object)
// with SNAT rules to NAT egress traffic from the pods that need a static egress IP
type EgressGateway struct {
	ipt *iptables.IPTables
}

const (
	defaultTimeOut            = 0
	defaultNATIptable         = "nat"
	egressGatewayNATChainName = "STATIC-EGRESS-NAT-CHAIN"
	defaultEgressChainName    = "STATIC-EGRESS-IP-CHAIN"
	egressGatewayFWChainName  = "STATIC-EGRESS-FORWARD-CHAIN"
	defaultPostRoutingChain   = "POSTROUTING"
	//customStaticEgressIPRouteTableID   = "99"
	staticEgressIPFWMARK               = "1000"
	//customStaticEgressIPRouteTableName = "static-egress-ip"
)

// NewEgressGateway is a constructor for EgressGateway interface
func NewEgressGateway() (*EgressGateway, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to locate iptables: %v", err)
	}
	return &EgressGateway{ipt: ipt}, nil
}

func (gateway *EgressGateway) Setup() error {

	// setup a chain to hold rules to accept forwarding traffic from director nodes with
	// out which default policy FORWARD chain of filter table drops the packet
	err := gateway.createChainIfNotExist("filter", egressGatewayFWChainName)
	if err != nil {
		return errors.New("Failed to add a chain in filter table required to permit forwarding traffic from director nodes" + err.Error())
	}

	ruleSpec := []string{"-j", egressGatewayFWChainName}
	hasRule, err := gateway.ipt.Exists("filter", "FORWARD", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in FORWARD chain of filter table to permit forward traffic from the directors" + err.Error())
	}
	if !hasRule {
		err = gateway.ipt.Append("filter", "FORWARD", ruleSpec...)
		if err != nil {
			return errors.New("Failed to add iptables command to permit traffic from directors to be forwrded in filter chain" + err.Error())
		}
	}

	// setup a chain in nat table to bypass run through the rules to snat traffic from the pods that need static egress ip
	err = gateway.ipt.NewChain("nat", egressGatewayNATChainName)
	if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
		return errors.New("Failed to add a " + egressGatewayNATChainName + " chain in NAT table" + err.Error())
	}
	ruleSpec = []string{"-j", egressGatewayNATChainName}
	hasRule, err = gateway.ipt.Exists("nat", "POSTROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify  rule exists in POSTROUTING chain of nat table due to " + err.Error())
	}
	if !hasRule {
		err = gateway.ipt.Insert("nat", "POSTROUTING", 1, ruleSpec...)
		if err != nil {
			return errors.New("Failed to run iptables command to add a rule to jump to STATIC-EGRESS-NAT-CHAIN chain due to " + err.Error())
		}
	}

	return nil
}

func (gateway *EgressGateway) creatingRoutingTable(setID string,setName string) error {

        // create custom routing table for directing the traffic from director nodes to the gateway node
        b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
        if err != nil {
                return errors.New("Failed to add custom routing table in /etc/iproute2/rt_tables needed for policy routing for directing traffing to egress gateway" + err.Error())
        }
        if !strings.Contains(string(b), setName) {
                f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
                if err != nil {
                        return errors.New("Failed to open /etc/iproute2/rt_tables to verify custom routing table " + setName + " required for static egress IP functionality due to " + err.Error())
                }
                defer f.Close()
                if _, err = f.WriteString(setID + " " + setName + "\n"); err != nil {
                        return errors.New("Failed to add custom routing table " + setName + " in /etc/iproute2/rt_tables needed for policy routing due to " + err.Error())
                }
        }

       // create policy based routing (ip rule) to lookup the custom routing table for FWMARK packets 
        out, err := exec.Command("ip", "rule", "list","table",setName).Output();
	//glog.Infof("List rule: %b - %s", strings.Contains(string(out), setName),string(out))
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }
	if !strings.Contains(string(out), "fwmark") {
		glog.Infof("Adding rule add prio 32764 fwmark %s table %s",string(staticEgressIPFWMARK), setName)
                err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", setName).Run()
                if err != nil {
                        return errors.New("Failed to add policy rule to lookup traffic marked with fwmark " + staticEgressIPFWMARK + " to the custom " + " routing table due to " + err.Error())
                } 
        }


        return nil
}

// AddStaticIptablesRule adds iptables rule for SNAT, creates source
// and destination IPsets. IPs can then be dynamically added to these IPsets.
func (gateway *EgressGateway) AddStaticIptablesRule(setID string,setName string, sourceIPs []string, destinationIP, egressIP string) error {
        // Create Routing Table
        err := gateway.creatingRoutingTable(setID,setName)
        if err != nil {
               return errors.New("Failed to create routing table " + setName + " due to %" + err.Error())
        }
	// create IPset from sourceIP's
	set, err := ipset.New(setName, "hash:ip", &ipset.Params{})
	if err != nil {
		return errors.New("Failed to create ipset with name " + setName + " due to %" + err.Error())
	}
	glog.Infof("Created ipset name: %s", setName)

	// add IP's that need to be part of the ipset
	for _, ip := range sourceIPs {
		err = set.Add(ip, 0)
		if err != nil {
			return errors.New("Failed to add an ip " + ip + " into ipset with name " + setName + " due to %" + err.Error())
		}
	}
	glog.Infof("Added ips %v to the ipset name: %s", sourceIPs, setName)

	ruleSpec := []string{"-m", "set", "--set", setName, "src", "-d", destinationIP, "-j", "ACCEPT"}
	hasRule, err := gateway.ipt.Exists("filter", egressGatewayFWChainName, ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in " + egressGatewayFWChainName + " chain of filter table" + err.Error())
	}
	if !hasRule {
		err = gateway.ipt.Append("filter", egressGatewayFWChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to add iptables command to ACCEPT traffic from director nodes to get forrwarded" + err.Error())
		}
	}
        // Get Rules
        out, err := exec.Command("ip", "rule", "list", "table", setName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
	}
	glog.Infof("Added rules in filter table FORWARD chain to permit traffic")
        for _, ip := range sourceIPs {
	  ruleSpec = []string{"-m", "set", "--match-set", setName, "src", "-d", ip, "-j", "SNAT", "--to-source", egressIP}
	  if err := gateway.insertRule(defaultNATIptable, egressGatewayNATChainName, 1, ruleSpec...); err != nil {
		return fmt.Errorf("failed to insert rule to chain %v err %v", defaultPostRoutingChain, err)
	  }
	  if !strings.Contains(string(out), ip) {
            glog.Infof("Adding rule from %s table %s",ip,setName)
	    err = exec.Command("ip", "rule", "add", "from" , ip, "table", setName).Run()
            if err != nil {
       		return errors.New("Failed to add rule table due to: " + err.Error())
            }
	  } 
        }

        // add routing entry in custom routing table to forward destinationIP to egressGateway
        out, err = exec.Command("ip", "route", "list", "table", setName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
        }

	if !strings.Contains(string(out),egressIP) {
          glog.Infof("Adding routing ip route add %s via %s table %s",destinationIP,egressIP,setName)
	  err = exec.Command("ip", "route", "add", destinationIP, "via", egressIP, "table", setName).Run()
          if err != nil {
       		return errors.New("Failed to add route in custom route table due to: " + err.Error())
          }
	}

	return nil
}

// DeleteStaticIptablesRule clears IPtables rules added by AddStaticIptablesRule
func (gateway *EgressGateway) ClearStaticIptablesRule(setID string,setName string, sourceIPs []string, destinationIP string, egressIP string) error {
        set, err := ipset.New(setName, "hash:ip", &ipset.Params{})
        if err != nil {
                return errors.New("Failed to get ipset with name " + setName + " due to %" + err.Error())
        }

	// delete rule in FORWARD chain of filter table
	ruleSpec := []string{"-m", "set", "--set", setName, "src", "-d", destinationIP, "-j", "ACCEPT"}
	hasRule, err := gateway.ipt.Exists("filter", egressGatewayFWChainName, ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in " + egressGatewayFWChainName + " chain of filter table" + err.Error())
	}
	if hasRule {
		err = gateway.ipt.Delete("filter", egressGatewayFWChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to delete iptables command to ACCEPT traffic from director nodes to get forwarded" + err.Error())
		}
	}

        // deleting routing entry in custom routing table to forward destinationIP to egressGateway
        _, err = exec.Command("ip", "route", "list", "table", setName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
        }
        
        glog.Infof("Deleting routing ip route add %s via %s table %s",destinationIP,egressIP,setName)
        exec.Command("ip", "route", "delete", destinationIP, "via", egressIP, "table", setName).Run()

        // Get Rules
        _, err = exec.Command("ip", "rule", "list", "table", setName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
        }
        for _, ip := range sourceIPs {
	  ruleSpec = []string{"-m", "set", "--match-set", setName, "src", "-d", ip, "-j", "SNAT", "--to-source", egressIP}
	  if err := gateway.deleteRule(defaultNATIptable, egressGatewayNATChainName, ruleSpec...); err != nil {
                return fmt.Errorf("failed to delete rule to chain %v err %v", defaultPostRoutingChain, err)
          }
          glog.Infof("Deleting rule from %s table %s",ip,setName)
          exec.Command("ip", "rule", "delete", "from" , ip, "table", setName).Run()
        }

        glog.Infof("Deleting rule add prio 32764 fwmark %s table %s",string(staticEgressIPFWMARK), setName)
        exec.Command("ip", "rule", "delete", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", setName).Run()

	err = set.Destroy()
	if err != nil {
		return errors.New("Failed to delete ipset due to " + err.Error())
	}

	return nil
} 

/*
// AddSourceIP
func (m *EgressGateway) AddSourceIP(ip string) error {
	return m.sourceIPSet.Add(ip, defaultTimeOut)
}

// DelSourceIP
func (m *EgressGateway) DelSourceIP(ip string) error {
	return m.sourceIPSet.Del(ip)
}

// AddDestIP
func (m *EgressGateway) AddDestIP(ip string) error {
	return m.destIPSet.Add(ip, defaultTimeOut)
}

// DelDestIP
func (m *EgressGateway) DelDestIP(ip string) error {
	return m.destIPSet.Del(ip)
}
*/
// CreateChainIfNotExist will check if chain exist, if not it will create one.
func (m *EgressGateway) createChainIfNotExist(table, chain string) error {
	err := m.ipt.NewChain(table, chain)
	if err == nil {
		return nil // chain didn't exist, created now.
	}
	eerr, eok := err.(*iptables.Error)
	if eok && eerr.ExitStatus() == 1 {
		return nil // chain already exists
	}
	return err
}

func (m *EgressGateway) deleteChain(table, chain string) error {
	return m.ipt.DeleteChain(table, chain)
}

func (m *EgressGateway) insertRule(table, chain string, pos int, ruleSpec ...string) error {
	exist, err := m.ipt.Exists(table, chain, ruleSpec...)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	return m.ipt.Insert(table, chain, pos, ruleSpec...)
}

func (m EgressGateway) deleteRule(table, chain string, ruleSpec ...string) error {
	return m.ipt.Delete(table, chain, ruleSpec...)
}
