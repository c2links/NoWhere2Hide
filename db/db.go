package db

import (
	"database/sql"
	"fmt"
	"nowhere2hide"
	"os"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "nowhere2hide"
	password = "nowhere2hide"
	dbname   = "nowhere2hide"
)

var log = logrus.New()

func init() {

	// Only log the debug severity or above.
	log.SetLevel(logrus.DebugLevel)

	// Log to file

	file, err := os.OpenFile("../logs/db.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("DB|Error|Failed to log to file, using default stderr")
	}
}

func InitDB() bool {

	c2_err := create_c2()
	if c2_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", c2_err))
		return false
	}

	banner_err := create_banner()
	if banner_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", banner_err))
		return false
	}

	status_err := create_status()
	if status_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", status_err))
		return false
	}

	tls_err := create_tls()
	if tls_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", status_err))
		return false
	}

	jarm_err := create_jarm()
	if jarm_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", status_err))
		return false
	}

	http_err := create_http()
	if http_err != nil {
		log.Info(fmt.Sprintf("DB|Error|%s", status_err))
		return false
	}
	return true
}

func create_status() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()

	if err != nil {
		return err
	}

	var status = "CREATE TABLE IF NOT EXISTS status " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"configs VARCHAR(255) NOT NULL, " +
		"job_started timestamp NOT NULL, " +
		"config_validated boolean NOT NULL, " +
		"targets_acquired boolean NOT NULL, " +
		"scan_started boolean NOT NULL, " +
		"scan_finished boolean NOT NULL,  " +
		"detection_started boolean NOT NULL , " +
		"detection_finished boolean NOT NULL, " +
		"errors text NOT NULL, " +
		"job_completed timestamp NOT NULL);"

	result, err := db.Exec(status)
	if err != nil {
		return err
	}

	log.Info(fmt.Sprintf("DB|Info|%s", result))

	defer db.Close()

	return nil

}

func create_c2() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()

	if err != nil {
		return err
	}

	var c2 = "CREATE TABLE IF NOT EXISTS c2_results " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"address VARCHAR(255) NOT NULL, " +
		"port VARCHAR(255) NOT NULL, " +
		"rule_name VARCHAR(255) NOT NULL, " +
		"malware_family VARCHAR(255) NOT NULL, " +
		"description VARCHAR(255) NOT NULL,  " +
		"classification VARCHAR(255) , " +
		"version VARCHAR(255), " +
		"additional_details VARCHAR(255) , " +
		"first_seen timestamp NOT NULL,  " +
		"last_seen timestamp NOT NULL);"

	result, err := db.Exec(c2)
	if err != nil {
		return err
	}

	log.Info(fmt.Sprintf("DB|Info|%s", result))

	defer db.Close()

	return nil

}

func create_banner() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	var banner = "CREATE TABLE IF NOT EXISTS banner " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"address VARCHAR(255) NOT NULL, " +
		"port VARCHAR(255) NOT NULL, " +
		"status VARCHAR(255) NOT NULL, " +
		"banner_hex TEXT, " +
		"banner_text TEXT, " +
		"banner_length INT, " +
		"timestamp timestamp NOT NULL);"

	results, err := db.Exec(banner)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", results))

	defer db.Close()

	return nil

}

func create_http() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	var http = "CREATE TABLE IF NOT EXISTS http " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"address VARCHAR(255) NOT NULL, " +
		"port VARCHAR(255) NOT NULL, " +
		"status VARCHAR(255) NOT NULL, " +
		"status_line VARCHAR(255) NOT NULL, " +
		"status_code INT NOT NULL, " +
		"protocol_name VARCHAR(255) NOT NULL, " +
		"headers TEXT NOT NULL, " +
		"body TEXT NOT NULL, " +
		"body_sha256 VARCHAR(255) NOT NULL, " +
		"timestamp timestamp NOT NULL);"

	results, err := db.Exec(http)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", results))

	defer db.Close()

	return nil

}

func create_tls() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	var tls = "CREATE TABLE IF NOT EXISTS tls " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"address VARCHAR(255) NOT NULL, " +
		"port VARCHAR(255) NOT NULL, " +
		"status VARCHAR(255) NOT NULL, " +
		"version INT, " +
		"serial_number VARCHAR(255), " +
		"issuer_common_name VARCHAR(255), " +
		"issuer_country VARCHAR(255), " +
		"issuer_organization VARCHAR(255), " +
		"issuer_dn VARCHAR(255), " +
		"subject_common_name VARCHAR(255), " +
		"subject_country VARCHAR(255), " +
		"subject_organization VARCHAR(255), " +
		"subject_dn VARCHAR(255), " +
		"fingerprint_md5 VARCHAR(255), " +
		"fingerprint_sha1  VARCHAR(255), " +
		"fingerprint_sha256  VARCHAR(255), " +
		"ja4x  VARCHAR(255), " +
		"timestamp timestamp NOT NULL);"

	results, err := db.Exec(tls)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", results))

	defer db.Close()

	return nil

}

func create_jarm() error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", host, port, user, password)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	var jarm = "CREATE TABLE IF NOT EXISTS jarm " +
		"(id SERIAL PRIMARY KEY, " +
		"uid VARCHAR(255) NOT NULL, " +
		"address VARCHAR(255) NOT NULL, " +
		"port VARCHAR(255) NOT NULL, " +
		"status VARCHAR(255) NOT NULL, " +
		"fingerprint  VARCHAR(255), " +
		"timestamp timestamp NOT NULL);"

	results, err := db.Exec(jarm)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", results))

	defer db.Close()

	return nil

}

func CheckC2Exists(c2_results nowhere2hide.C2Results) (bool, error) {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return false, err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return false, err
	}

	//Check if record already exists

	rows, err := db.Query(`SELECT "address","port","rule_name","malware_family" FROM "c2_results"`)
	if err != nil {
		return false, err
	}

	new_record := c2_results.Address + c2_results.Port + c2_results.Rule_Name + c2_results.Malware_Family
	for rows.Next() {
		var address string
		var port string
		var rule_name string
		var malware_family string

		err = rows.Scan(&address, &port, &rule_name, &malware_family)
		if err != nil {
			return false, err
		}

		record := address + port + rule_name + malware_family
		if record == new_record {
			db.Close()
			return true, nil

		}

	}

	db.Close()
	return false, nil

}

func AddC2(c2_results nowhere2hide.C2Results) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `insert into "c2_results"("uid", "address", "port", "malware_family", "rule_name","description","classification","version","additional_details","first_seen", "last_seen")` +
		`values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,$11)`

	result, err := db.Exec(insertDynStmt, c2_results.UID, c2_results.Address, c2_results.Port, c2_results.Malware_Family, c2_results.Rule_Name, c2_results.Description, c2_results.Classification, c2_results.Version, c2_results.Additional_Details, c2_results.First_Seen, c2_results.Last_Seen)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", result))

	defer db.Close()
	return nil

}

func AddHTTP(db_http nowhere2hide.DB_HTTP) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `insert into "http"("uid", "address", "port", "status", "status_line","status_code", "protocol_name", "headers","body", "body_sha256", "timestamp")` +
		`values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	result, err := db.Exec(insertDynStmt, db_http.Uid, db_http.Address, db_http.Port, db_http.Status, db_http.Status_Line, db_http.Status_Code, db_http.Protocol_Name,
		db_http.Headers, db_http.Body, db_http.Body_SHA256, db_http.Timestamp)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", result))

	defer db.Close()
	return nil
}

func AddJarm(db_jarm nowhere2hide.DB_JARM) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `insert into "jarm"("uid", "address", "port", "status","fingerprint","timestamp")` +
		`values($1, $2, $3, $4, $5, $6)`

	result, err := db.Exec(insertDynStmt, db_jarm.Uid, db_jarm.Address, db_jarm.Port, db_jarm.Status, db_jarm.JARM_Fingerprint, db_jarm.Timestamp)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", result))

	defer db.Close()
	return nil
}

func AddBanner(db_banner nowhere2hide.DB_Banner) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `insert into "banner"("uid", "address", "port", "status","banner_hex","banner_text","banner_length","timestamp")` +
		`values($1, $2, $3, $4, $5, $6, $7,$8)`

	result, err := db.Exec(insertDynStmt, db_banner.Uid, db_banner.Address, db_banner.Port, db_banner.Status, db_banner.Banner_Hex, db_banner.Banner_Text, db_banner.Banner_Length, db_banner.Timestamp)

	if err != nil {
		result, err := db.Exec(insertDynStmt, db_banner.Uid, db_banner.Address, db_banner.Port, db_banner.Status, db_banner.Banner_Hex, "<NOWHERE2HIDE ERROR: COULDN'T CONVERT TEXT", db_banner.Banner_Length, db_banner.Timestamp)
		if err != nil {
			return err
		} else {
			log.Info(fmt.Sprintf("DB|Info|%s", result))
		}
		defer db.Close()

	} else {
		log.Info(fmt.Sprintf("DB|Info|%s", result))
	}
	return nil
}

func tlsCheck(fingerprint_sha256 string) (bool, string, error) {

	var uid string
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		db.Close()
		return false, uid, err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		db.Close()
		return false, uid, err
	}

	rows, err := db.Query(`SELECT "uid","fingerprint_sha256" FROM "tls"`)
	if err != nil {
		db.Close()
		return false, uid, err
	}

	for rows.Next() {
		var tls_fingerprint_sha256 string

		err = rows.Scan(&uid, &tls_fingerprint_sha256)
		if err != nil {
			db.Close()
			return false, uid, err
		}

		if tls_fingerprint_sha256 == fingerprint_sha256 {
			db.Close()
			return true, uid, nil

		}

	}

	db.Close()
	return false, uid, nil

}

func AddTLS(db_tls nowhere2hide.DB_TLS) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	exists, uid, err := tlsCheck(db_tls.Fingerprint_SHA256)
	if err != nil {
		log.Info(fmt.Sprintf("TLS Check Error: %s", err))
	}

	if !exists {
		insertDynStmt := `insert into "tls"("uid", "address", "port", "status","version","serial_number","issuer_common_name","issuer_country",` +
			`"issuer_organization","issuer_dn","subject_common_name","subject_country","subject_organization","subject_dn","fingerprint_md5","fingerprint_sha1",` +
			`"fingerprint_sha256","ja4x","timestamp") values($1, $2, $3, $4, $5, $6, $7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`

		result, err := db.Exec(insertDynStmt, db_tls.Uid, db_tls.Address, db_tls.Port, db_tls.Status, db_tls.Version, db_tls.Serial_Number, db_tls.Issuer_Common_Name, db_tls.Issuer_Country,
			db_tls.Issuer_Organization, db_tls.Issuer_DN, db_tls.Subject_Common_Name, db_tls.Subject_Country, db_tls.Subject_Organization, db_tls.Subject_DN,
			db_tls.Fingerprint_Md5, db_tls.Fingerprint_SHA1, db_tls.Fingerprint_SHA256, db_tls.JA4X, db_tls.Timestamp)

		if err != nil {
			return err
		} else {
			log.Info(fmt.Sprintf("DB|TLS|Info|%s", result))
		}
	} else {
		log.Info(fmt.Sprintf("DB|TLS Check|Info|Already Exists: %s", db_tls.Fingerprint_SHA256))
		insertDynStmt := `update "tls" set "timestamp" = $1 where "uid" = $2`

		results, err := db.Exec(insertDynStmt, db_tls.Timestamp, uid)
		if err != nil {
			log.Info(fmt.Sprintf("DB|TLS Check|Error|%s", err))
		}
		log.Info(fmt.Sprintf("DB|TLS|Info|%s", results))

	}
	defer db.Close()
	return nil
}

func AddStatus(job_status *nowhere2hide.Job_Status) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `insert into "status" ("uid", "configs","job_started","config_validated", "targets_acquired", "scan_started","scan_finished","detection_started","detection_finished","errors","job_completed")` +
		`values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	result, err := db.Exec(insertDynStmt, job_status.UID, job_status.Configs, job_status.Job_Started, job_status.Config_Validated, job_status.Targets_Acquired, job_status.Scan_Started, job_status.Scan_Finished, job_status.Detection_Started, job_status.Detection_Finished, job_status.Errors, job_status.Job_Completed)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|STATUS|Info|%s", result))

	defer db.Close()
	return nil

}

func UpdateStatus(job_status *nowhere2hide.Job_Status) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `update "status" set "job_started" = $1, "configs" = $2, "config_validated" = $3,  "targets_acquired" = $4, "scan_started" = $5,"scan_finished" = $6, "detection_started" = $7, "detection_finished" = $8, "job_completed" = $9, "errors" = $10 where "uid" = $11`

	result, err := db.Exec(insertDynStmt, job_status.Job_Started, job_status.Configs, job_status.Config_Validated, job_status.Targets_Acquired, job_status.Scan_Started, job_status.Scan_Finished, job_status.Detection_Started, job_status.Detection_Finished, job_status.Job_Completed, job_status.Errors, job_status.UID)

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Status|Info|%s", result))

	defer db.Close()
	return nil

}

func UpdateC2(c2_results nowhere2hide.C2Results) error {

	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		return err
	}

	insertDynStmt := `update "c2_results" set "last_seen" = $1 where "uid" = $2`

	results, err := db.Exec(insertDynStmt, c2_results.Last_Seen, c2_results.UID)
	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|C2|Info|%s", results))

	defer db.Close()
	return nil

}

func BannerQuery(query string) ([]nowhere2hide.DB_Banner, error) {
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		defer db.Close()
		return nil, err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		defer db.Close()
		return nil, err
	}

	var results []nowhere2hide.DB_Banner
	rows, err := db.Query(query)

	if err != nil {
		defer db.Close()
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var result nowhere2hide.DB_Banner
		var id int
		if err := rows.Scan(&id, &result.Uid, &result.Address, &result.Port, &result.Status, &result.Banner_Hex, &result.Banner_Text, &result.Banner_Length, &result.Timestamp); err != nil {
			db.Close()
			return nil, err
		}
		results = append(results, result)

	}
	db.Close()
	return results, nil
}

func TLSQuery(query string) ([]nowhere2hide.DB_TLS, error) {
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		defer db.Close()
		return nil, err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		defer db.Close()
		return nil, err
	}

	var results []nowhere2hide.DB_TLS
	rows, err := db.Query(query)

	if err != nil {
		defer db.Close()
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var result nowhere2hide.DB_TLS
		var id int
		if err := rows.Scan(&id, &result.Uid, &result.Address, &result.Port, &result.Status, &result.Version, &result.Serial_Number, &result.Issuer_Common_Name, &result.Issuer_Country,
			&result.Issuer_Organization, &result.Issuer_DN, &result.Subject_Common_Name, &result.Subject_Organization, &result.Subject_Organization, &result.Subject_DN,
			&result.Fingerprint_Md5, &result.Fingerprint_SHA1, &result.Fingerprint_SHA256); err != nil {
			db.Close()
			return nil, err
		}
		results = append(results, result)

	}
	db.Close()
	return results, nil
}

func Query(table string, query string) ([]nowhere2hide.DB_Gen, error) {
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname =%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		defer db.Close()
		return nil, err
	}

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	if err != nil {
		defer db.Close()
		return nil, err
	}

	var results []nowhere2hide.DB_Gen
	rows, err := db.Query(fmt.Sprintf("select uid,address,port,timestamp from %s where %s", table, query))

	if err != nil {
		defer db.Close()
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var result nowhere2hide.DB_Gen
		//var id int
		if err := rows.Scan(&result.Uid, &result.Address, &result.Port, &result.Timestamp); err != nil {
			db.Close()
			return nil, err
		}
		results = append(results, result)

	}
	db.Close()
	return results, nil
}
