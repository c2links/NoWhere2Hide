package main

import (
	// The sql go library is needed to interact with the database
	"database/sql"
	"fmt"
)

type Store interface {
	GetC2() ([]*C2_Record, error)
	GetC2Query(query string) ([]*C2_Record, error)
	ExecuteQuery(query string, limit string, offset string) (QueryResult, error)
	GetJobs() ([]*Job_Status, error)
	GetRecordCountQ(query string) (int, error)
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

	rows, err := store.db.Query("SELECT address, port, malware_family, rule_name, first_seen, last_seen FROM c2_results")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c2List := []*C2_Record{}
	for rows.Next() {
		c2 := &C2_Record{}
		if err := rows.Scan(&c2.IP, &c2.Port, &c2.Malware_Family, &c2.Rule_Name, &c2.First_Seen, &c2.Last_Seen); err != nil {
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

func (store *dbStore) GetRecordCountQ(query string) (int, error) {

	type CountRecord struct {
		Count int
	}

	var count CountRecord

	rows, err := store.db.Query(fmt.Sprintf("SELECT count(*) FROM (%s) AS subquery", query))

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

	rows, err := store.db.Query(fmt.Sprintf("SELECT address, port, malware_family, rule_name, first_seen, last_seen FROM c2_results where malware_family ilike '%%%s%%' ORDER BY last_seen DESC ", query))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c2List := []*C2_Record{}
	for rows.Next() {
		c2 := &C2_Record{}
		if err := rows.Scan(&c2.IP, &c2.Port, &c2.Malware_Family, &c2.Rule_Name, &c2.First_Seen, &c2.Last_Seen); err != nil {
			return nil, err
		}
		c2List = append(c2List, c2)
	}
	return c2List, nil
}

func (store *dbStore) ExecuteQuery(query string, limit string, offset string) (QueryResult, error) {

	var results QueryResult
	rows, err := store.db.Query(fmt.Sprintf("%s ORDER BY timestamp DESC LIMIT %s OFFSET %s", query, limit, offset))

	if err != nil {
		return results, err
	}
	defer rows.Close()

	columns, err := rows.Columns()

	if err != nil {
		return results, err
	}

	results.Columns = columns

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))

		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return results, err
		}

		results.Rows = append(results.Rows, values)
	}
	return results, nil
}

func (store *dbStore) GetJobs() ([]*Job_Status, error) {

	rows, err := store.db.Query("SELECT uid, configs,job_started,config_validated,targets_acquired,scan_started,scan_finished,detection_started,detection_finished,job_completed,errors FROM status ORDER BY job_started DESC LIMIT 500")
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
