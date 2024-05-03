package main

import (
	"fmt"
	"io/fs"
	"nowhere2hide"
	"nowhere2hide/collector"
	"nowhere2hide/db"
	"nowhere2hide/detect"
	"nowhere2hide/scan"
	"path/filepath"
	"time"

	"os"

	"github.com/beevik/guid"
	"gopkg.in/yaml.v2"
)

/*
	This functions acts as a gateway from the UI to the actual NOWHERE2HIDE scanning engine.
	It receives a list of the scans to run and for each scan in the list, it will facilitate the:

	1. Retrieval of the targets
	2. Initialization and execution of the scanning
	3. C2 detections

	This function also updates the Status table for each job as it pushes through each stage

*/

func Run(configPaths []string) string {

	// Log to file
	file, err := os.OpenFile("../logs/run.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("Run|Error|Failed to log to file, using default stderr")
	}

	runGUID := guid.New()

	t := time.Now()

	var js nowhere2hide.Job_Status
	js.UID = runGUID.String()
	js.Configs = ""
	js.Job_Started = t.Format("2006-01-02 15:04:05")
	js.Config_Validated = false
	js.Targets_Acquired = false
	js.Scan_Started = false
	js.Scan_Finished = false
	js.Detection_Started = false
	js.Detection_Finished = false
	js.Job_Completed = t.Format("2006-01-02 15:04:05")
	js.Errors = ""

	err = db.AddStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		//return err.Error()
	}

	var configs []*nowhere2hide.C2_Config
	all := false

	for _, configPath := range configPaths {
		if configPath == "all" {
			all = true
		}
	}

	if all {
		js.Configs = "all"
		err = db.UpdateStatus(&js)
		if err != nil {
			log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
			return err.Error()
		}
	}

	// Loop through the supplied configs and add them to a list of C2_Config structs to be processed
	if all {

		fileError := filepath.WalkDir(runArgs.Signatures, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				var config nowhere2hide.C2_Config

				yamlFile, err := os.ReadFile(fmt.Sprintf("%s/%s", runArgs.Signatures, d.Name()))
				if err != nil {
					log.Info(fmt.Sprintf("Run|%s|Error|Error reading YAML File|%s", runGUID, err))

				}

				err = yaml.Unmarshal(yamlFile, &config)
				if err != nil {
					log.Info(fmt.Sprintf("Run|%s|Error|Error parsing YAML File|%s", runGUID, err))
				}

				configs = append(configs, &config)
			}
			return nil
		})
		if fileError != nil {
			log.Info(fmt.Sprintf("Run|%s|Error|Error parsing YAML File|%s", runGUID, err))
		}

	} else {

		config_string := ""

		for _, configPath := range configPaths {
			if configPath != "c2-auth" {

				config_string = config_string + configPath + "\n"
				var config nowhere2hide.C2_Config

				yamlFile, err := os.ReadFile(fmt.Sprintf("%s/%s", runArgs.Signatures, configPath))
				if err != nil {
					log.Info(fmt.Sprintf("Run|%s|Error|Error reading YAML File|%s", runGUID, err))
					return err.Error()

				}

				err = yaml.Unmarshal(yamlFile, &config)
				if err != nil {
					log.Info(fmt.Sprintf("Run|%s|Error|Error parsing YAML File|%s", runGUID, err))
					return err.Error()
				}

				configs = append(configs, &config)

			}
		}
		if len(config_string) > 255 {
			js.Configs = config_string[0:255]
		} else {
			js.Configs = config_string
		}

		err = db.UpdateStatus(&js)
		if err != nil {
			log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
			return err.Error()

		}
	}

	js.Config_Validated = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	// Acquire Targets

	var targets []*nowhere2hide.Scan

	targets, err = collector.Collect(configs, runGUID.String())
	if err != nil {
		return err.Error()
	}

	js.Targets_Acquired = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	log.Info(fmt.Sprintf("Run|%s|Info|Starting Scans on %d Targets", runGUID, len(targets)))

	// Start Scans
	js.Scan_Started = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	scan.Run(targets, "zgrab2", runGUID.String())

	// Run Detections
	js.Scan_Finished = true
	js.Detection_Started = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	log.Info(fmt.Sprintf("Run|%s|Info|Running Detections", runGUID))
	detect.Detect(configs, runGUID.String())

	//Finalize
	t = time.Now()
	js.Detection_Finished = true
	js.Job_Completed = t.Format("2006-01-02 15:04:05")
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("Run|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}
	log.Info(fmt.Sprintf("Run|%s|Info|Completed", runGUID))

	return "Successfully Started Scan"
}

func RunHuntCerts() string {

	var err error
	// Log to file
	file, err := os.OpenFile("../logs/run.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("RunHuntCert|Error|Failed to log to file, using default stderr")
	}

	runGUID := guid.New()
	t := time.Now()

	var js nowhere2hide.Job_Status
	js.UID = runGUID.String()
	js.Job_Started = t.Format("2006-01-02 15:04:05")
	js.Config_Validated = true
	js.Configs = "HUNTIO CERTS"
	js.Targets_Acquired = true
	js.Scan_Started = false
	js.Scan_Finished = false
	js.Detection_Started = true
	js.Detection_Finished = true
	js.Job_Completed = t.Format("2006-01-02 15:04:05")

	err = db.AddStatus(&js)

	if err != nil {
		log.Info(fmt.Sprintf("RunHuntCert|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	js.Scan_Started = true
	err = db.UpdateStatus(&js)

	if err != nil {
		log.Info(fmt.Sprintf("RunHuntCert|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	log.Info(fmt.Sprintf("RunHuntCert|%s|Info|Running Hunt IO Cert Collections", runGUID))
	var targets []*nowhere2hide.Scan
	scan.Run(targets, "hunt_certs", runGUID.String())
	js.Scan_Finished = true

	//Finalize
	t = time.Now()
	js.Detection_Finished = true
	js.Job_Completed = t.Format("2006-01-02 15:04:05")
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("RunHuntCert|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}
	log.Info(fmt.Sprintf("RunHuntCert|%s|Info|Complete, Now running retro scans", runGUID))
	RunRetro()
	log.Info(fmt.Sprintf("RunHuntCert|%s|Info|All actions completed", runGUID))
	return "Successful"
}

func RunRetro() string {

	// Log to file
	file, err := os.OpenFile("../logs/run.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("RunRetro|Error|Failed to log to file, using default stderr")
	}

	runGUID := guid.New()

	t := time.Now()

	var js nowhere2hide.Job_Status
	js.UID = runGUID.String()
	js.Job_Started = t.Format("2006-01-02 15:04:05")
	js.Config_Validated = false
	js.Configs = "Retro C2s"
	js.Targets_Acquired = false
	js.Scan_Started = false
	js.Scan_Finished = false
	js.Detection_Started = false
	js.Detection_Finished = false
	js.Job_Completed = t.Format("2006-01-02 15:04:05")

	err = db.AddStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("RunRetro|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	var configs []*nowhere2hide.C2_Config

	fileError := filepath.WalkDir(runArgs.Signatures, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			var config nowhere2hide.C2_Config

			yamlFile, err := os.ReadFile(fmt.Sprintf("%s/%s", runArgs.Signatures, d.Name()))
			if err != nil {
				log.Info(fmt.Sprintf("RunRetro|%s|Error|Error reading YAML File|%s", runGUID, err))

			}

			err = yaml.Unmarshal(yamlFile, &config)
			if err != nil {
				log.Info(fmt.Sprintf("RunRetro|%s|Error|Error parsing YAML File|%s", runGUID, err))
			}

			configs = append(configs, &config)
		}
		return nil
	})

	if fileError != nil {
		log.Info(fmt.Sprintf("RunRetro|%s|Error|Error parsing YAML File|%s", runGUID, err))
	}

	js.Config_Validated = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("RunRetro|%s|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	js.Detection_Started = true
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("RunRetro|%s|Error updating Status %s", runGUID, err))
		return err.Error()
	}

	log.Info(fmt.Sprintf("RunRetro|%s|Info|Running Detections", runGUID))
	detect.Detect(configs, runGUID.String())

	//Finalize
	t = time.Now()
	js.Detection_Finished = true
	js.Job_Completed = t.Format("2006-01-02 15:04:05")
	err = db.UpdateStatus(&js)
	if err != nil {
		log.Info(fmt.Sprintf("RunRetro|%s|Error|Error updating Status %s", runGUID, err))
		return err.Error()
	}
	log.Info(fmt.Sprintf("RunRetro|%s|Info|Complete", runGUID))

	return "Successful"
}
