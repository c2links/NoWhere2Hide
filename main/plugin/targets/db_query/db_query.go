package main

import (
	"fmt"
	"net"
	"nowhere2hide"
	"nowhere2hide/db"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Create a new instance of the logger.
var log = logrus.New()

type DB_Query struct{}

// Logging Function
func (m DB_Query) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|DB_Query|Error|Failed to log to file, using default stderr"))
	}
}

func (m DB_Query) Get_Name() string {
	return "database_query"
}

func (m DB_Query) Get_QueryBox() bool {
	return true
}

func (m DB_Query) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()
	Target_Source_Identifier := "database_query"

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

var Collect DB_Query

func (m DB_Query) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	var targets []nowhere2hide.Target

	resulting_query := strings.Split(strings.ToLower(query), "from")[1]

	results, err := db.ExecuteQuery(fmt.Sprintf("FROM %s", resulting_query))

	if err != nil {
		log.Info(fmt.Sprintf("Collect|DB_Query|Error|Error collecting IP's / Ports|%s", err))
		return targets
	}

	for _, target := range results {

		port, _ := strconv.Atoi(target.Port)
		var temp nowhere2hide.Target
		temp.Port = port
		temp.Target = target.Address
		temp.Target_Type = "IP"
		targets = append(targets, temp)
	}
	return targets

}
