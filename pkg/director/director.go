package director

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/janeczku/go-ipset/ipset"
)

const (
	//customStaticEgressIPRouteTableID   = "99"
	//customStaticEgressIPRouteTableName = "static-egress-ip"
	staticEgressIPFWMARK               = "1000"
	bypassCNIMasquradeChainName        = "STATIC-EGRESS-BYPASS-CNI"
)

// EgressDirector manages routing rules needed on a node to redirect egress traffic from the pods that need
// a static egress IP to a node acting as egress gateway based on the `staticegressip` CRD object
type EgressDirector struct {
	ipt *iptables.IPTables
}

// NewEgressDirector is a constructor for EgressDirector
func NewEgressDirector() (*EgressDirector, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to locate iptables: %v", err)
	}

	return &EgressDirector{ipt: ipt}, nil
}

// Setup sets up the node with one-time basic settings needed for director functionality
func (d *EgressDirector) Setup() error {

	// create custom routing table for directing the traffic from director nodes to the gateway node
	/*b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to add custom routing table in /etc/iproute2/rt_tables needed for policy routing for directing traffing to egress gateway" + err.Error())
	}
	if !strings.Contains(string(b), customStaticEgressIPRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed to open /etc/iproute2/rt_tables to verify custom routing table " + customStaticEgressIPRouteTableName + " required for static egress IP functionality due to " + err.Error())
		}
		defer f.Close()
		if _, err = f.WriteString(customStaticEgressIPRouteTableID + " " + customStaticEgressIPRouteTableName + "\n"); err != nil {
			return errors.New("Failed to add custom routing table " + customStaticEgressIPRouteTableName + " in /etc/iproute2/rt_tables needed for policy routing due to " + err.Error())
		}
	}

	// create policy based routing (ip rule) to lookup the custom routing table for FWMARK packets
	out, err := exec.Command("ip", "rule", "list","table","routingName").Output()
	if err != nil {
		return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
	}
	
	if !strings.Contains(string(out), routingName) {
		glog.Infof("Adding rule add prio fwmark %s table %s"string(staticEgressIPFWMARK),routingName)
		err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", routingName).Run()
		if err != nil {
			return errors.New("Failed to add policy rule to lookup traffic marked with fwmark " + staticEgressIPFWMARK + " to the custom " + " routing table due to " + err.Error())
		}
	} */

	// setup a chain in nat table to bypass the CNI masqurade for the traffic bound to egress gateway
	err := d.ipt.NewChain("nat", bypassCNIMasquradeChainName)
	if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
		return errors.New("Failed to add a " + bypassCNIMasquradeChainName + " chain in NAT table required to bypass CNI masqurading due to" + err.Error())
	}
	ruleSpec := []string{"-j", bypassCNIMasquradeChainName}
	hasRule, err := d.ipt.Exists("nat", "POSTROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify bypass CNI masqurade rule exists in POSTROUTING chain of nat table due to " + err.Error())
	}
	if !hasRule {
		err = d.ipt.Insert("nat", "POSTROUTING", 1, ruleSpec...)
		if err != nil {
			return errors.New("Failed to run iptables command to add a rule to jump to STATIC_EGRESSIP_BYPASS_CNI_MASQURADE chain due to " + err.Error())
		}
	}

	glog.Infof("Node has been setup for static egress IP director functionality successfully.")

	return nil
}

func (d *EgressDirector) creatingRoutingTable(routingID string,routingName string) error {
	
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

        // create policy based routing (ip rule) to lookup the custom routing table for FWMARK packets
        out, err := exec.Command("ip", "rule", "list","table",routingName).Output()
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }
        if !strings.Contains(string(out), "fwmark") {
		//glog.Infof("List output: %s",string(out))
		glog.Infof("Adding rule creating add prio 32764 fwmark %s table %s",string(staticEgressIPFWMARK),routingName)
                err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", routingName).Run()
                if err != nil {
                        return errors.New("Failed to add policy rule to lookup traffic marked with fwmark " + staticEgressIPFWMARK + " to the custom " + " routing table due to " + err.Error())
                }
        }

	return nil
}

// AddRouteToGateway adds a routes on the director node to redirect traffic from a set of pod IP's
// (selected by service name in the rule of staticegressip CRD object) to a specific
// destination CIDR to be directed to egress gateway node
func (d *EgressDirector) AddRouteToGateway(routingID string,routingName string, sourceIPs []string, destinationIP, egressGateway string) error {

	// Create Routing Table
	err := d.creatingRoutingTable(routingID,routingName)
	if err != nil {
		return errors.New("Failed to create routing table " + routingName + " due to %" + err.Error())
	}
	// create IPset for the set of sourceIP's
	set, err := ipset.New(routingName, "hash:ip", &ipset.Params{})
	if err != nil {
		return errors.New("Failed to create ipset with name " + routingName + " due to %" + err.Error())
	}
	glog.Infof("Created ipset name: %s", routingName)

	// add IP's that need to be part of the ipset
	for _, ip := range sourceIPs {
		err = set.Add(ip, 0)
		if err != nil {
			return errors.New("Failed to add an ip " + ip + " into ipset with name " + routingName + " due to %" + err.Error())
		}
	}
	glog.Infof("Added ips %v to the ipset name: %s", sourceIPs, routingName)

	// create iptables rule in mangle table PREROUTING chain to match src to ipset created and destination
	// matching  destinationIP then fwmark the packets
	ruleSpec := []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "MARK", "--set-mark", staticEgressIPFWMARK}
	hasRule, err := d.ipt.Exists("mangle", "PREROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
	}
	if !hasRule {
		err = d.ipt.Insert("mangle", "PREROUTING", 1, ruleSpec...)
		if err != nil {
			return errors.New("Failed to add rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
		}
		glog.Infof("added rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP")
	}
	glog.Infof("iptables rule in mangle table PREROUTING chain to match src to ipset")

	ruleSpec = []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "ACCEPT"}
	hasRule, err = d.ipt.Exists("nat", bypassCNIMasquradeChainName, ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in BYPASS_CNI_MASQURADE chain of nat table to bypass the CNI masqurade" + err.Error())
	}
	if !hasRule {
		err = d.ipt.Append("nat", bypassCNIMasquradeChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to run iptables command to add a rule to ACCEPT traffic in BYPASS_CNI_MASQURADE chain" + err.Error())
		}
	}

	// add routing entry in custom routing table to forward destinationIP to egressGateway
	out, err := exec.Command("ip", "route", "list", "table", routingName).Output()
	if err != nil {
		return errors.New("Failed to verify required default route to gateway exists. " + err.Error())
	}
        
	if !strings.Contains(string(out), strings.Replace(destinationIP,"0.0.0.0/0","default",1)) && strings.Contains(egressGateway,".") {
		glog.Infof("Adding routing ip route add %s via %s table %s",destinationIP,egressGateway,routingName)
		if err = exec.Command("ip", "route", "add", destinationIP, "via", egressGateway, "table", routingName).Run(); err != nil {
	 		return errors.New("Failed to add route in custom route table due to: " + err.Error())
		}
	}

	glog.Infof("added routing entry in custom routing table to forward destinationIP to egressGateway")

	return nil
}

// DeleteRouteToGateway removes the route routes on the director node to redirect traffic to gateway node
func (d *EgressDirector) DeleteRouteToGateway(routingID string,routingName string, sourceIPs []string,destinationIP, egressGateway string) error {

	set, err := ipset.New(routingName, "hash:ip", &ipset.Params{})
	if err != nil {
		return errors.New("Failed to get ipset with name " + routingName + " due to %" + err.Error())
	}

	// create iptables rule in mangle table PREROUTING chain to match src to ipset created and destination
	// matching  destinationIP then fwmark the packets
	ruleSpec := []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "MARK", "--set-mark", staticEgressIPFWMARK}
	hasRule, err := d.ipt.Exists("mangle", "PREROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
	}
	if hasRule {
		err = d.ipt.Delete("mangle", "PREROUTING", ruleSpec...)
		if err != nil {
			return errors.New("Failed to delete rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
		}
		glog.Infof("deleted rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP")
	}

	ruleSpec = []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "ACCEPT"}
	hasRule, err = d.ipt.Exists("nat", bypassCNIMasquradeChainName, ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in BYPASS_CNI_MASQURADE chain of nat table to bypass the CNI masqurade" + err.Error())
	}
	if hasRule {
		err = d.ipt.Delete("nat", bypassCNIMasquradeChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to delete iptables command to add a rule to ACCEPT traffic in BYPASS_CNI_MASQURADE chain" + err.Error())
		}
	}

	// add routing entry in custom routing table to forward destinationIP to egressGateway
	_, err = exec.Command("ip", "route", "list", "table", routingName).Output()
	if err != nil {
		return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
	}
	glog.Infof("Deleting ip route delete %s via %s table %s",destinationIP,egressGateway,routingName)
        exec.Command("ip", "route", "delete", destinationIP, "via", egressGateway, "table", routingName).Run()
        glog.Infof("deleted route")

        // create policy based routing (ip rule) to lookup the custom routing table for FWMARK packets
        _, err = exec.Command("ip", "rule", "list","table",routingName).Output()
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }
        
	glog.Infof("Deleting rule delete prio 32764 fwmark %s table %s",string(staticEgressIPFWMARK),routingName)
        exec.Command("ip", "rule", "delete", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", routingName).Run()

        err = set.Destroy()
        if err != nil {
                return errors.New("Failed to delete ipset due to " + err.Error())
        }

	return nil
}

func (d *EgressDirector) ClearStaleRouteToGateway(routingID string,routingName string, destinationIP, egressGateway string) error {

	// create iptables rule in mangle table PREROUTING chain to match src to ipset created and destination
	// matching  destinationIP then fwmark the packets
	ruleSpec := []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "MARK", "--set-mark", staticEgressIPFWMARK}
	hasRule, err := d.ipt.Exists("mangle", "PREROUTING", ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
	}
	if hasRule {
		err = d.ipt.Delete("mangle", "PREROUTING", ruleSpec...)
		if err != nil {
			return errors.New("Failed to delete rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP" + err.Error())
		}
		glog.Infof("deleted rule in PREROUTING chain of mangle table to fwmark egress traffic that needs static egress IP")
	}

	ruleSpec = []string{"-m", "set", "--set", routingName, "src", "-d", destinationIP, "-j", "ACCEPT"}
	hasRule, err = d.ipt.Exists("nat", bypassCNIMasquradeChainName, ruleSpec...)
	if err != nil {
		return errors.New("Failed to verify rule exists in BYPASS_CNI_MASQURADE chain of nat table to bypass the CNI masqurade" + err.Error())
	}
	if hasRule {
		err = d.ipt.Delete("nat", bypassCNIMasquradeChainName, ruleSpec...)
		if err != nil {
			return errors.New("Failed to delete iptables command to add a rule to ACCEPT traffic in BYPASS_CNI_MASQURADE chain" + err.Error())
		}
	}

	// add routing entry in custom routing table to forward destinationIP to egressGateway
	_, err = exec.Command("ip", "route", "list", "table", routingName).Output()
	if err != nil {
		return errors.New("Failed to verify required default route to gatewat exists. " + err.Error())
	}

	glog.Infof("Deleting ip route delete %s via %s table %s",destinationIP,egressGateway,routingName)
	exec.Command("ip", "route", "delete", destinationIP, "via", egressGateway, "table", routingName).Run()
	glog.Infof("deleted route")

        // delete policy based routing (ip rule) to lookup the custom routing table for FWMARK packets
        _, err = exec.Command("ip", "rule", "list","table",routingName).Output()
        if err != nil {
                return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
        }
        
	glog.Infof("Deleting rule delete prio 32764 fwmark %s table %s",string(staticEgressIPFWMARK),routingName)
        exec.Command("ip", "rule", "delete", "prio", "32764", "fwmark", staticEgressIPFWMARK, "table", routingName).Run()

	return nil
}
