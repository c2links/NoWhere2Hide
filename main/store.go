package main

import (
	// The sql go library is needed to interact with the database
	"database/sql"
	"fmt"
)

type Store interface {
	GetC2() ([]*C2_Record, error)
	GetC2Query(query string) ([]*C2_Record, error)
	GetBanner(limit string, offset string) ([]*Banner_Record, error)
	GetBannerQuery(query string, limit string, offset string) ([]*Banner_Record, error)
	GetJarm(limit string, offset string) ([]*Jarm_Record, error)
	GetJarmQuery(query string, limit string, offset string) ([]*Jarm_Record, error)
	GetHTTP(limit string, offset string) ([]*HTTP_Record, error)
	GetHTTPQuery(query string, limit string, offset string) ([]*HTTP_Record, error)
	GetTLS(limit string, offset string) ([]*TLS_Record, error)
	GetTLSQuery(query string, limit string, offset string) ([]*TLS_Record, error)
	GetJobs() ([]*Job_Status, error)
	GetRecordCount(table string) (int, error)
	GetRecordCountQ(table string, query string) (int, error)
	GetC2List() ([]*C2_Count, error)
	deleteContents(string) error
	CheckTokenExists(inputToken string) (error, bool)
	CheckAdminExists() bool
	AddAdminToken(token string) error
	GetAdminToken() (error, string)
}

// `dbStore` struct implements the `Store` interface. Variable `db` takes the pointer
// to the SQL database connection object.

type dbStore struct {
	db *sql.DB
}

// Create a global `store` variable of type `Store` interface. It will be initialized
// in `func main()`.
var store Store

func (store *dbStore) AddAdminToken(token string) error {

	insertDynStmt := "insert into token (token, username)" +
		`values($1, $2)`

	result, err := store.db.Exec(insertDynStmt, token, "admin")

	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("DB|Info|%s", result))

	return nil

}

func (store *dbStore) GetAdminToken() (error, string) {

	rows, err := store.db.Query("SELECT token,username FROM token")
	if err != nil {
		return err, ""
	}

	for rows.Next() {
		var token string
		var user string

		err = rows.Scan(&token, &user)
		if err != nil {
			return err, ""
		}

		if user == "admin" {
			return nil, token

		}
	}
	return err, ""
}

func (store *dbStore) CheckAdminExists() bool {

	rows, err := store.db.Query("SELECT token,username FROM token")
	if err != nil {
		return false
	}

	for rows.Next() {
		var token string
		var user string

		err = rows.Scan(&token, &user)
		if err != nil {
			return false
		}

		if user == "admin" {
			return true

		}
	}

	return false

}

func (store *dbStore) CheckTokenExists(inputToken string) (error, bool) {

	rows, err := store.db.Query("SELECT token,username FROM token")
	if err != nil {
		return err, false
	}

	for rows.Next() {
		var token string
		var user string

		err = rows.Scan(&token, &user)
		if err != nil {
			return err, false
		}

		if inputToken == token {
			return nil, true

		}
	}

	return nil, false

}

func (store *dbStore) GetC2() ([]*C2_Record, error) {

	rows, err := store.db.Query("SELECT address, port, malware_family FROM c2_results")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c2List := []*C2_Record{}
	for rows.Next() {
		c2 := &C2_Record{}
		if err := rows.Scan(&c2.IP, &c2.Port, &c2.Malware_Family); err != nil {
			return nil, err
		}
		c2List = append(c2List, c2)
	}
	return c2List, nil
}

func (store *dbStore) GetC2List() ([]*C2_Count, error) {

	rows, err := store.db.Query("SELECT DISTINCT (malware_family),count(malware_family) from c2_results group by malware_family")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c2List := []*C2_Count{}
	for rows.Next() {
		c2 := &C2_Count{}
		if err := rows.Scan(&c2.Malware_Family, &c2.Count); err != nil {
			return nil, err
		}
		c2List = append(c2List, c2)
	}
	return c2List, nil
}

func (store *dbStore) GetRecordCount(table string) (int, error) {

	type CountRecord struct {
		Count int
	}

	var count CountRecord

	rows, err := store.db.Query(fmt.Sprintf("SELECT count(id) FROM %s", table))

	if err != nil {
		return 0, err
	}
	for rows.Next() {
		if err := rows.Scan(&count.Count); err != nil {
			return 0, err
		}

	}

	return count.Count, nil
}

func (store *dbStore) GetRecordCountQ(table string, query string) (int, error) {

	type CountRecord struct {
		Count int
	}

	var count CountRecord

	rows, err := store.db.Query(fmt.Sprintf("SELECT count(id) FROM %s WHERE %s", table, query))

	if err != nil {
		return 0, err
	}
	for rows.Next() {
		if err := rows.Scan(&count.Count); err != nil {
			return 0, err
		}

	}

	return count.Count, nil
}

func (store *dbStore) GetC2Query(query string) ([]*C2_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address, port, malware_family FROM c2_results where malware_family ilike '%%%s%%'", query))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c2List := []*C2_Record{}
	for rows.Next() {
		c2 := &C2_Record{}
		if err := rows.Scan(&c2.IP, &c2.Port, &c2.Malware_Family); err != nil {
			return nil, err
		}
		c2List = append(c2List, c2)
	}
	return c2List, nil
}

func (store *dbStore) GetBanner(limit string, offset string) ([]*Banner_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address, port, status, banner_text, banner_hex, banner_length, timestamp FROM banner ORDER BY address LIMIT %s OFFSET %s", limit, offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bannerList := []*Banner_Record{}
	for rows.Next() {
		banner := &Banner_Record{}
		if err := rows.Scan(&banner.Address, &banner.Port, &banner.Status, &banner.Banner_Text, &banner.Banner_Hex, &banner.Banner_Length, &banner.Timestamp); err != nil {
			return nil, err
		}
		bannerList = append(bannerList, banner)
	}
	return bannerList, nil
}

func (store *dbStore) GetTLS(limit string, offset string) ([]*TLS_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status,version ,serial_number,issuer_common_name,"+
		"issuer_country, issuer_organization,issuer_dn,subject_common_name,subject_country,subject_organization,subject_dn,fingerprint_sha1, ja4x, timestamp  FROM tls "+
		"ORDER BY address LIMIT %s OFFSET %s", limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tlsList := []*TLS_Record{}
	for rows.Next() {
		tls := &TLS_Record{}
		if err := rows.Scan(&tls.Address, &tls.Port, &tls.Status, &tls.Version, &tls.Serial_Number, &tls.Issuer_Common_Name, &tls.Issuer_Country, &tls.Issuer_Organization, &tls.Issuer_DN,
			&tls.Subject_Common_Name, &tls.Subject_Country, &tls.Subject_Organization, &tls.Subject_DN, &tls.Fingerprint_SHA1, &tls.JA4X, &tls.Timestamp); err != nil {
			return nil, err
		}
		tlsList = append(tlsList, tls)
	}
	return tlsList, nil
}

func (store *dbStore) GetJarm(limit string, offset string) ([]*Jarm_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status,fingerprint,timestamp FROM jarm "+
		"ORDER BY address LIMIT %s OFFSET %s", limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jarmList := []*Jarm_Record{}
	for rows.Next() {
		jarm := &Jarm_Record{}
		if err := rows.Scan(&jarm.Address, &jarm.Port, &jarm.Status, &jarm.Fingerprint, &jarm.Timestamp); err != nil {
			return nil, err
		}
		jarmList = append(jarmList, jarm)
	}
	return jarmList, nil
}

func (store *dbStore) GetHTTP(limit string, offset string) ([]*HTTP_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status, status_line,status_code,headers,body,body_sha256, timestamp FROM http "+
		"ORDER BY address LIMIT %s OFFSET %s", limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	httpList := []*HTTP_Record{}
	for rows.Next() {
		http := &HTTP_Record{}
		if err := rows.Scan(&http.Address, &http.Port, &http.Status, &http.Status_Line, &http.Status_Code, &http.Headers, &http.Body, &http.Body_SHA256, &http.Timestamp); err != nil {
			return nil, err
		}
		httpList = append(httpList, http)
	}
	return httpList, nil
}

func (store *dbStore) GetBannerQuery(query string, limit string, offset string) ([]*Banner_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address, port, status, banner_text, banner_hex, banner_length, timestamp FROM banner WHERE %s ORDER BY address LIMIT %s OFFSET %s", query, limit, offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bannerList := []*Banner_Record{}
	for rows.Next() {
		banner := &Banner_Record{}
		if err := rows.Scan(&banner.Address, &banner.Port, &banner.Status, &banner.Banner_Text, &banner.Banner_Hex, &banner.Banner_Length, &banner.Timestamp); err != nil {
			return nil, err
		}
		bannerList = append(bannerList, banner)
	}

	return bannerList, nil
}

func (store *dbStore) GetTLSQuery(query string, limit string, offset string) ([]*TLS_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status,version ,serial_number,"+
		"issuer_common_name, issuer_country, issuer_organization,issuer_dn,"+
		"subject_common_name,subject_country,subject_organization,subject_dn,fingerprint_sha1, ja4x, timestamp  FROM tls WHERE %s "+
		"ORDER BY address LIMIT %s OFFSET %s", query, limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tlsList := []*TLS_Record{}
	for rows.Next() {
		tls := &TLS_Record{}
		if err := rows.Scan(&tls.Address, &tls.Port, &tls.Status, &tls.Version, &tls.Serial_Number, &tls.Issuer_Common_Name, &tls.Issuer_Country, &tls.Issuer_Organization, &tls.Issuer_DN,
			&tls.Subject_Common_Name, &tls.Subject_Country, &tls.Subject_Organization, &tls.Subject_DN, &tls.Fingerprint_SHA1, &tls.JA4X, &tls.Timestamp); err != nil {
			return nil, err
		}
		tlsList = append(tlsList, tls)
	}
	return tlsList, nil
}

func (store *dbStore) GetJarmQuery(query string, limit string, offset string) ([]*Jarm_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status,fingerprint,timestamp FROM jarm WHERE %s "+
		"ORDER BY address LIMIT %s OFFSET %s", query, limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jarmList := []*Jarm_Record{}
	for rows.Next() {
		jarm := &Jarm_Record{}
		if err := rows.Scan(&jarm.Address, &jarm.Port, &jarm.Status, &jarm.Fingerprint, &jarm.Timestamp); err != nil {
			return nil, err
		}
		jarmList = append(jarmList, jarm)
	}
	return jarmList, nil
}

func (store *dbStore) GetHTTPQuery(query string, limit string, offset string) ([]*HTTP_Record, error) {

	rows, err := store.db.Query(fmt.Sprintf("SELECT address,port,status, status_line,status_code,headers,body,body_sha256, timestamp FROM http WHERE %s "+
		"ORDER BY address LIMIT %s OFFSET %s", query, limit, offset))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	httpList := []*HTTP_Record{}
	for rows.Next() {
		http := &HTTP_Record{}
		if err := rows.Scan(&http.Address, &http.Port, &http.Status, &http.Status_Line, &http.Status_Code, &http.Headers, &http.Body, &http.Body_SHA256, &http.Timestamp); err != nil {
			return nil, err
		}
		httpList = append(httpList, http)
	}
	return httpList, nil
}

func (store *dbStore) GetJobs() ([]*Job_Status, error) {

	rows, err := store.db.Query("SELECT uid, configs,job_started,config_validated,targets_acquired,scan_started,scan_finished,detection_started,detection_finished,job_completed,errors FROM status ORDER BY job_started DESC LIMIT 20")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jobList := []*Job_Status{}
	for rows.Next() {
		status := &Job_Status{}
		if err := rows.Scan(&status.UID, &status.Configs, &status.Job_Started, &status.Config_Validated, &status.Targets_Acquired, &status.Scan_Started, &status.Scan_Finished, &status.Detection_Started, &status.Detection_Finished, &status.Job_Completed, &status.Errors); err != nil {
			return nil, err
		}
		jobList = append(jobList, status)
	}
	return jobList, nil
}

func (store *dbStore) deleteContents(table string) error {
	// Perform the delete operation (you might need to customize this based on your schema)
	_, err := store.db.Exec(fmt.Sprintf("DELETE FROM %s", table))
	if err != nil {
		return err
	}
	return nil
}
