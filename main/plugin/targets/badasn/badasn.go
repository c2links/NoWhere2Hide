package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"nowhere2hide"
	"nowhere2hide/utils"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type BADASN struct{}

// Create a new instance of the logger.
var log = logrus.New()

// Logging Function
func (m BADASN) Init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)
	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info("Collect|badasn|Error|Error: Failed to log to file, using default stderr")
	}
}

func (m BADASN) Get_Name() string {
	return "badasn"
}

func (m BADASN) Get_QueryBox() bool {
	return false
}

// Main collector function. Required arguments are the C2_config and the runGUID. Most collectors will also need a query. however this is not a required field.
func (m BADASN) Run(c2_config *nowhere2hide.C2_Config, query string, runGUID string) []*nowhere2hide.Scan {

	m.Init()

	Target_Source_Identifier := "BADASN"

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

func (m BADASN) Get_Targets(query string, runGUID string) []nowhere2hide.Target {

	// These functions have no form and are to collect and normalize the data into the Target structures

	ctx := context.Background()
	owner := "c2links"
	repo := "drop_asn_port_scan"
	branch := "main"
	filename := "out/asn_port_scan.json.gz"

	var msr []nowhere2hide.MassScan_Results

	content, err := utils.GetFile(ctx, owner, repo, branch, filename)

	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|badasn|Error|Error retrieving file from Git repo", runGUID))
	}

	gzData := []byte(content)
	gzBuffer := bytes.NewBuffer(gzData)

	gzipReader, err := gzip.NewReader(gzBuffer)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
	}
	defer gzipReader.Close()

	// Read the decompressed data from the gzip reader

	decompressedData, err := ioutil.ReadAll(gzipReader)
	if err != nil {
		fmt.Println("Error reading decompressed data:", err)

	}

	err = json.Unmarshal(decompressedData, &msr)
	if err != nil {
		log.Info(fmt.Sprintf("Collect|%s|badasn|Error|Error with JSON -> %s", runGUID, err))
	}

	log.Info(fmt.Sprintf("Collect|%s|badasn|Info|BADASN, Hits-> %d", runGUID, len(msr)))

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

var Collect BADASN

// Helper functions go here. These can be anything, but will typically be functions that call out to the collector API to get the data into the main collector function
