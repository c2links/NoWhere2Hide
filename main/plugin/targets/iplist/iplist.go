package main

import (
	"fmt"
	"net"
	"nowhere2hide"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Create a new instance of the logger.
var log = logrus.New()

type IPLIST struct{}

// Logging Function
func (m IPLIST) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|iplist|Error|Failed to log to file, using default stderr"))
	}
}

func (m IPLIST) Get_Name() string {
	return "iplist"
}

func (m IPLIST) Get_QueryBox() bool {
	return true
}

func (m IPLIST) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()
	Target_Source_Identifier := "iplist"

	targets := m.Get_Targets(query, runGUID)

	var final_targets []*nowhere2hide.Scan

	for _, target := range targets {

		var zgrabScanTarget zgrab2.ScanTarget
		if target.Target_Type == "IP" {
			zgrabScanTarget.IP = net.ParseIP(target.Target)

			var temp nowhere2hide.Scan
			temp.Config = c2_config
			temp.Port = strconv.Itoa(target.Port)
			temp.Target = target.Target
			temp.ZTarget = zgrabScanTarget
			temp.Type = target.Target_Type
			temp.TargetSource = Target_Source_Identifier
			final_targets = append(final_targets, &temp)
		}
	}

	return final_targets
}

var Collect IPLIST

func (m IPLIST) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	var targets []nowhere2hide.Target

	ips := strings.Split(query, ",")

	for _, target := range ips {
		var temp nowhere2hide.Target
		ip_port := strings.Split(target, ":")
		port, err := strconv.Atoi(ip_port[1])

		if err != nil {
			port = 443
		}

		temp.Target_Type = "IP" // Type can be IP / Domain / URL
		temp.Target = ip_port[0]
		temp.Port = port
		targets = append(targets, temp)
	}

	return targets

}
