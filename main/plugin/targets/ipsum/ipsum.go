package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"nowhere2hide"
	"nowhere2hide/utils"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type IPSUM struct{}

// Create a new instance of the logger.
var log = logrus.New()

// Logging Function
func (m IPSUM) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|ipsum|Error|Failed to log to file, using default stderr"))
	}
}

func (m IPSUM) Get_Name() string {
	return "ipsum"
}

func (m IPSUM) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()
	Target_Source_Identifier := "IPSUM"

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

func (m IPSUM) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	/*
		// If API keys are needed to pull data, then uncomment this block. API keys should be stored in api.yaml.

		api_keys, err := utils.LoadAPI()
		if err != nil {
			log.Info(fmt.Sprintf("RUN_GUID: %s, Phase: Collect, <Collector> -> %s, Error: %s", runGUID, err))
			return targets
		}
	*/

	ctx := context.Background()
	owner := "c2links"
	repo := "ipsum_port_scan"
	branch := "main"
	filename := "out/ipsum_port_scan.json"
	var msr []nowhere2hide.MassScan_Results

	content, err := utils.GetFile(ctx, owner, repo, branch, filename)

	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|ipsum|Error|Error retrieving file from Git repo", runGUID))
	}

	err = json.Unmarshal([]byte(content), &msr)
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|ipsum|Error|Error with JSON -> %s", runGUID, err))
	}

	log.Info(fmt.Sprintf("Collect|%s|ipsum|Info|Hits-> %d", runGUID, len(msr)))

	var targets []nowhere2hide.Target

	for _, target := range msr {
		for _, port := range target.Ports {
			var temp nowhere2hide.Target
			temp.Target_Type = "IP" // Type can be IP / Domain / URL
			temp.Target = target.IP
			temp.Port = port.Port
			targets = append(targets, temp)
		}
	}

	return targets
}

var Collect IPSUM

// Helper functions go here. These can be anything, but will typically be functions that call out to the collector API to get the data into the main collector function
