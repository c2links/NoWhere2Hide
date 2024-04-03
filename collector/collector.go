package collector

import (
	"fmt"
	"nowhere2hide"
	"nowhere2hide/utils"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/sirupsen/logrus"
)

// Structs needed to parse / save target data go here

// Create a new instance of the logger.
var log = logrus.New()

func init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)
}

func Collect(c2_configs []*nowhere2hide.C2_Config, runGUID string) ([]*nowhere2hide.Scan, error) {

	var targets []*nowhere2hide.Scan
	//var scantargets nowhere2hide.ScanTargets

	// Log to file
	file, err := os.OpenFile("../logs/collect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info(fmt.Sprintf("Collect|%s|Error|Failed to log to file, using default stderr", runGUID))
		return targets, err
	}

	ROOT_DIR := "../main/plugin/targets"
	// Step 1: Collect RAW data to process (ASN Drop, Censys, Shodan)
	for _, c2_config := range c2_configs {
		for _, target := range c2_config.Targets {

			err := filepath.Walk(ROOT_DIR, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					log.Info(fmt.Sprintf("Collect|%s|Error|Error with loading plugins -> %s", runGUID, err))

				}
				if !info.IsDir() && strings.Contains(info.Name(), ".so") {

					p, err := plugin.Open(path)
					if err != nil {
						log.Info(fmt.Sprintf("Collect|%s|Error| with loading plugins -> %s", runGUID, err))
					}

					collectInstance, err := p.Lookup("Collect")
					if err != nil {
						log.Info(fmt.Sprintf("Collect|%s|Error| with loading plugins -> %s", runGUID, err))
					}

					collectFunc := collectInstance.(nowhere2hide.Collection)
					if collectFunc.Get_Name() == target.Source {
						for _, query := range target.TargetQuery {
							targets = append(targets, collectFunc.Run(c2_config, query, runGUID)...)
						}

					}

				}
				return nil
			})
			if err != nil {
				log.Info(fmt.Sprintf("Collect|%s|Error|Error with loading plugins -> %s", runGUID, err))
			}

		}
	}

	// Step 2: Process / Normalize Raw data into ScanTarget structs

	var ports []string
	var ips []string

	for _, v := range targets {
		ports = append(ports, v.Port)
		if v.Type == "IP" {
			ips = append(ips, v.Target)
		}
	}

	ips_final := utils.DedupeStringSlice(ips)
	log.Info(fmt.Sprintf("Collect|%s|Info|Total unique IP's -> %d", runGUID, len(ips_final)))
	log.Info(fmt.Sprintf("Collect|%s|Info|Total unique Ports -> %d", runGUID, len(utils.DedupeStringSlice(ports))))
	log.Info(fmt.Sprintf("Collect|%s|Info|Total Targets -> %d", runGUID, len(targets)))

	// Step 3: Return slice of ScanTarget structs

	return targets, nil
}
