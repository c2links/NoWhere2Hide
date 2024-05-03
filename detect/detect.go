package detect

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"nowhere2hide"
	"nowhere2hide/db"
	"nowhere2hide/utils"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)
	file, err := os.OpenFile("../logs/detect.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.Out = file
	} else {
		log.Info("Detect|Error|Failed to log to file, using default stderr")
	}
}

func Detect(configs []*nowhere2hide.C2_Config, runGUID string) {

	for _, config := range configs {

		if config.Detection.Module {

			ROOT_DIR := "../main/plugin/c2"
			err := filepath.Walk(ROOT_DIR, func(path string, info os.FileInfo, err error) error {

				if !info.IsDir() && strings.Contains(info.Name(), ".so") {

					p, err := plugin.Open(path)
					if err != nil {
						log.Info(fmt.Sprintf("Detect|%s|Error|Error with opening plugins -> %s", runGUID, err))
					}

					detectInstance, err := p.Lookup("Detect")
					if err != nil {
						log.Info(fmt.Sprintf("Detect|%s|Error|Error with loading plugins -> %s", runGUID, err))
					}

					detectFunc := detectInstance.(nowhere2hide.Detectors)

					if detectFunc.Get_Name() == config.Detection.Module_name {
						banner_http := detectFunc.Get_Payload_Type()

						if banner_http == "banner" {
							results, err := db.BannerQuery(fmt.Sprintf("select * from banner where uid = '%s'", runGUID))
							if err != nil {
								log.Info(fmt.Sprintf("Detect|%s|Error|Error getting banner hex -> %s", runGUID, err))
							}
							for _, banner := range results {
								var c2D nowhere2hide.C2Detector

								bannerSlice, err := hex.DecodeString(banner.Banner_Hex)
								if err != nil {
									log.Info(fmt.Sprintf("Detect|%s|Error|Error converting banner hex -> %s", runGUID, err))
								}
								if len(bannerSlice) > 0 {
									c2D.Banner_Payload = bannerSlice
									res := detectFunc.Process(c2D)

									if res.Valid {

										var c2s nowhere2hide.C2Results
										c2s.UID = utils.GetMD5Hash(fmt.Sprintf("%s_%s_%s", config.Rule_Name, banner.Address, banner.Port))
										c2s.Address = banner.Address
										c2s.Port = banner.Port
										c2s.Malware_Family = config.Family
										c2s.Rule_Name = config.Rule_Name
										c2s.Classification = config.Classification
										c2s.Description = config.Description
										c2s.Additional_Details = res.Additional
										c2s.First_Seen = banner.Timestamp
										c2s.Last_Seen = banner.Timestamp

										addC2(c2s, runGUID)
									}
								}

							}

						}

						if banner_http == "http" {
							fmt.Print("hi")

						}

					}

				}
				return nil
			})
			if err != nil {
				log.Info(fmt.Sprintf("Detect|%s|Error with detection modules|%s", runGUID, err))
			}
		}

		if config.Detection.Simple {
			if config.Detection.Condition == "any" {
				for _, q := range config.Detection.Queries {
					results, err := db.Query(q.Table, q.Query)
					if err != nil {
						log.Info(fmt.Sprintf("Detect|%s|Error simple module db query| %s", runGUID, err))
					}
					for _, result := range results {

						var c2s nowhere2hide.C2Results
						c2s.UID = utils.GetMD5Hash(fmt.Sprintf("%s_%s_%s", config.Rule_Name, result.Address, result.Port))
						c2s.Address = result.Address
						c2s.Port = result.Port
						c2s.Malware_Family = config.Family
						c2s.Rule_Name = config.Rule_Name
						c2s.Classification = config.Classification
						c2s.Description = config.Description
						c2s.Additional_Details = ""
						c2s.First_Seen = result.Timestamp
						c2s.Last_Seen = result.Timestamp

						addC2(c2s, runGUID)

					}

				}
			}
		}

		if config.Detection.Condition == "all" {

			type ALL struct {
				uid    string
				record nowhere2hide.C2Results
				count  int
			}

			var allRecords []*ALL
			var first = true
			var qCount = len(config.Detection.Queries)

			for _, q := range config.Detection.Queries {
				results, err := db.Query(q.Table, q.Query)
				if err != nil {
					log.Info(fmt.Sprintf("Detect|%s|Error simple all query db query| %s", runGUID, err))
				}

				for _, result := range results {

					var c2s nowhere2hide.C2Results
					c2s.UID = utils.GetMD5Hash(fmt.Sprintf("%s_%s_%s", config.Rule_Name, result.Address, result.Port))
					c2s.Address = result.Address
					c2s.Port = result.Port
					c2s.Malware_Family = config.Family
					c2s.Rule_Name = config.Rule_Name
					c2s.Classification = config.Classification
					c2s.Description = config.Description
					c2s.Additional_Details = ""
					c2s.First_Seen = result.Timestamp
					c2s.Last_Seen = result.Timestamp

					if first {

						var temp ALL
						temp.uid = c2s.UID
						temp.record = c2s
						temp.count = 1
						allRecords = append(allRecords, &temp)

					} else {
						for _, all := range allRecords {
							if all.uid == c2s.UID {
								all.count++
							}
						}

					}
				}
				first = false
			}

			for _, all := range allRecords {
				if all.count == qCount {
					addC2(all.record, runGUID)
				}
			}
		}
	}
}

func addC2(c2s nowhere2hide.C2Results, runGUID string) {

	connString := utils.GetConnectionString()
	dbConn, err := sql.Open("postgres", connString)

	if err != nil {
		log.Info(fmt.Sprintf("Detect|%s|Error|Error connection DB-> %s", runGUID, err))
		dbConn.Close()
	}

	// close database
	defer dbConn.Close()

	// check db
	err = dbConn.Ping()
	if err != nil {
		log.Info(fmt.Sprintf("Detect|%s|Error|Error ping DB-> %s", runGUID, err))
		dbConn.Close()

	}

	exists, err := db.CheckC2Exists(dbConn, c2s)

	if err != nil {
		log.Info(fmt.Sprintf("Detect|%s|Error CheckExists| %s", runGUID, err))
	}

	if !exists {
		err = db.AddC2(dbConn, c2s)

		if err != nil {
			log.Info(fmt.Sprintf("Detect|%s|Error Add C2| %s", runGUID, err))

		} else {
			log.Info(fmt.Sprintf("Detect|%s|Info|Added to C2 database: %+v", runGUID, c2s))
		}

	} else {
		err = db.UpdateC2(dbConn, c2s)

		if err != nil {
			log.Info(fmt.Sprintf("Detect|%s|Error Update C2| %s", runGUID, err))
		} else {
			log.Info(fmt.Sprintf("Detect|%s|Info|Record already existed in C2 database: %+v", runGUID, c2s))
		}
	}
	dbConn.Close()
}
