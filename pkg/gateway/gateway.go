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
	defaultTimeOut            int    = 0
	defaultNATIptable         string = "nat"
	egressGatewayNATChainName string = "STATIC-EGRESS-NAT-CHAIN"
	defaultEgressChainName    string = "STATIC-EGRESS-IP-CHAIN"
	egressGatewayFWChainName  string = "STATIC-EGRESS-FORWARD-CHAIN"
	defaultPostRoutingChain   string = "POSTROUTING"
	bypassCNIMasquradeChainName string = "STATIC-EGRESS-BYPASS-CNI"
)

// NewEgressGateway is a constructor for EgressGateway interface
func NewEgressGateway() (*EgressGateway, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to locate iptables: %v", err)
	}
	return &EgressGateway{ipt: ipt}, nil
}

func (d *EgressGateway) Setup() error {

	// setup a chain to hold rules to accept forwarding traffic from director nodes with
	// out which default policy FORWARD chain of filter table drops the packet
	err := d.createChainIfNotExist("filter", egressGatewayFWChainName)
	if err != nil {
		return errors.New("Failed to add a chain in filter table required to permit forwarding traffic from director nodes" + err.Error())
	}

	ruleSpec := []string{"-j", egressGatewayFWChainName}
	hasRule, err := d.ipt.Exists("filter", "FORWARD", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in FORWARD chain of filter table to permit forward traffic from the directors" + err.Error())
	}
	if !hasRule {
		err = d.ipt.Append("filter", "FORWARD", ruleSpec...)
		if err != nil {
			return errors.New("Failed to add iptables command to permit traffic from directors to be forwrded in filter chain" + err.Error())
		}
	}

	// setup a chain in nat table to bypass run through the rules to snat traffic from the pods that need static egress ip
	err = d.ipt.NewChain("nat", egressGatewayNATChainName)
	if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
		return errors.New("Failed to add a " + egressGatewayNATChainName + " chain in NAT table" + err.Error())
	}
	ruleSpec = []string{"-j", egressGatewayNATChainName}
	hasRule, err = d.ipt.Exists("nat", "POSTROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify  rule exists in POSTROUTING chain of nat table due to " + err.Error())
	}
	if !hasRule {
		err = d.ipt.Insert("nat", "POSTROUTING", 1, ruleSpec...)
		if err != nil {
			return errors.New("Failed to run iptables command to add a rule to jump to STATIC-EGRESS-NAT-CHAIN chain due to " + err.Error())
		}
	}

	glog.Infof("Node has been setup for static egress IP gateway functionality successfully.")

	return nil
}

func (d *EgressGateway) creatingRoutingTable(routingID string,routingName string) error {

        // create custom routing table for directing the traffic from director nodes to the gateway node
        b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
        if err != nil {
                return errors.New("Failed to add custom routing table in /etc/iproute2/rt_tables needed for policy routing for directing traffing to egress gateway" + err.Error())
        }
        if !strings.Contains(string(b), routingName) {
                f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
                if err != nil {
                        return errors.New("Failed to open /etc/iproute2/rt_tables to verify custom routing table " + routingName + " required for static egress IP functionality due to " + err.Error())
                }
                defer f.Close()
                if _, err = f.WriteString(routingID + " " + routingName + "\n"); err != nil {
                        return errors.New("Failed to add custom routing table " + routingName + " in /etc/iproute2/rt_tables needed for policy routing due to " + err.Error())
                }
        }

        out, err := exec.Command("ip", "rule", "list").Output()
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }

        if !strings.Contains(string(out), routingName) {
                glog.Infof("Adding rule add prio fwmark %s table %s",routingID,routingName)
                err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", routingID, "table", routingName).Run()
                if err != nil {
                        return errors.New("Failed to add policy rule to lookup traffic marked with fwmark " + routingID + " to the custom " + " routing table due to " + err.Error())
                }
        }

        return nil
}

// AddStaticIptablesRule adds iptables rule for SNAT, creates source
// and destination IPsets. IPs can then be dynamically added to these IPsets.
func (d *EgressGateway) AddStaticIptablesRule(routingID string,routingName string, tableName string,sourceIPs []string, destinationIP, egressIP string) error {
       // Create Routing Table
        err := d.creatingRoutingTable(routingID,routingName)
        if err != nil {
               return errors.New("Failed to create routing table " + routingName + " due to %" + err.Error())
        }
	// create IPset from sourceIP's
	set, err := ipset.New(tableName, "hash:ip", &ipset.Params{})
	if err != nil {
		return errors.New("Failed to create ipset with name " + tableName + " due to %" + err.Error())
	}
	glog.Infof("Created ipset name: %s", tableName)

	// add IP's that need to be part of the ipset
	for _, ip := range sourceIPs {
		err = set.Add(ip, 0)
		if err != nil {
			return errors.New("Failed to add an ip " + ip + " into ipset with name " + tableName + " due to %" + err.Error())
		}
	

		ruleSpec := []string{"-m", "set", "--set", tableName, "src", "-s", ip, "-j", "ACCEPT"}
		hasRule, err := d.ipt.Exists("filter", egressGatewayFWChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to verify rule exists in " + egressGatewayFWChainName + " chain of filter table" + err.Error())
		}
		if !hasRule {
			err = d.ipt.Append("filter", egressGatewayFWChainName, ruleSpec...)
			if err != nil {
				return errors.New("Failed to add iptables command to ACCEPT traffic from director nodes to get forrwarded" + err.Error())
			}
		}
	        glog.Infof("Added rules in filter table FORWARD chain to permit traffic")
        
	  	ruleSpec = []string{"-m", "set", "--match-set", tableName, "src", "-d", ip, "-j", "SNAT", "--to-source", egressIP}
		if err := d.insertRule(defaultNATIptable, egressGatewayNATChainName, 1, ruleSpec...); err != nil {
			return fmt.Errorf("failed to insert rule to chain %v err %v", defaultPostRoutingChain, err)
	  	}
        }
	glog.Infof("Added ips %v to the ipset name: %s", sourceIPs, tableName)

        // add routing entry in custom routing table to forward destinationIP to egressGateway
        out, err := exec.Command("ip", "route", "list", "table", routingName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gateway exists. " + err.Error())
        }

        if !strings.Contains(string(out), strings.Replace(destinationIP,"0.0.0.0/0","default",1)) && strings.Contains(egressIP,".") {
          glog.Infof("Adding routing ip route add %s via %s table %s",destinationIP,egressIP,routingName)
	  err = exec.Command("ip", "route", "add", destinationIP, "via", egressIP, "table", routingName).Run()
          if err != nil {
       		return errors.New("Failed to add route in custom route table due to: " + err.Error())
          }
	}

	return nil
}

// DeleteStaticIptablesRule clears IPtables rules added by AddStaticIptablesRule
func (d *EgressGateway) DeleteStaticIptablesRule(routingID string,routingName string, tableName string, sourceIPs []string, destinationIP string, egressIP string) error {
        set, err := ipset.New(tableName, "hash:ip", &ipset.Params{})
        if err != nil {
                return errors.New("Failed to get ipset with name " + tableName + " due to %" + err.Error())
        }

        for _, ip := range sourceIPs {
		// delete rule in NAT postrouting to SNAT traffic
		ruleSpec := []string{"-m", "set", "--match-set", tableName, "src", "-s", ip, "-j", "SNAT", "--to-source", egressIP}
		if err := d.deleteRule(defaultNATIptable, egressGatewayNATChainName, ruleSpec...); err != nil {
			return fmt.Errorf("failed to delete rule in chain %v err %v", egressGatewayNATChainName, err)
		}

		// delete rule in FORWARD chain of filter table
		ruleSpec = []string{"-m", "set", "--set", tableName, "src", "-s", ip, "-j", "ACCEPT"}
		hasRule, err := d.ipt.Exists("filter", egressGatewayFWChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to verify rule exists in " + egressGatewayFWChainName + " chain of filter table" + err.Error())
		}
		if hasRule {
			err = d.ipt.Delete("filter", egressGatewayFWChainName, ruleSpec...)
			if err != nil {
				return errors.New("Failed to delete iptables command to ACCEPT traffic from director nodes to get forwarded" + err.Error())
			}
		}
	}
        _, err = exec.Command("ip", "route", "list", "table", routingName).Output()
        if err != nil {
                return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
        }

        //glog.Infof("Deleting routing ip route add %s via %s table %s",destinationIP,egressIP,routingName)
        //exec.Command("ip", "route", "delete", destinationIP, "via", egressIP, "table", routingName).Run()
        //glog.Infof("deleted route")

        // create policy based routing (ip rule) to lookup the custom routing table for FWMARK packets
        _, err = exec.Command("ip", "rule", "list").Output()
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }

        //glog.Infof("Deleting rule delete prio 32764 fwmark %s table %s",routingID,routingName)
        //exec.Command("ip", "rule", "delete", "prio", "32764", "fwmark", routingID, "table", routingName).Run()

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
