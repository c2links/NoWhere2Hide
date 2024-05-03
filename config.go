package nowhere2hide

/*
This contains the structs needed to parse the C2 Config YAMLs.
*/

type Scan_Banner struct {
	Enabled   bool
	Probefile string
}

type Custom_Header struct {
	Field string
	Value string
}

type Scan_HTTP struct {
	Enabled         bool
	Method          string
	Endpoint        string
	Useragent       string
	Body            string
	Custom_Headers  []Custom_Header
	FailHTTPtoHTTPs bool
	RetryHTTPS      bool
	HTTPS           bool
}

type Scan_TLS struct {
	Enabled bool
}

type Scan_JARM struct {
	Enabled bool
}

type C2_Target struct {
	Source      string
	TargetQuery []string
}

type Detection_Query struct {
	Table string
	Query string
}

type Detection struct {
	Module      bool
	Module_name string
	Simple      bool
	Condition   string
	Queries     []Detection_Query
}

type C2_Config struct {
	Rule_Name      string
	GUID           string
	Family         string
	Version        string
	Description    string
	Classification string
	References     []string
	Created        string
	Targets        []C2_Target
	Scan_Banner    Scan_Banner
	Scan_HTTP      Scan_HTTP
	Scan_TLS       Scan_TLS
	Scan_JARM      Scan_JARM
	Detection      Detection
}
