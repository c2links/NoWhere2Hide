package nowhere2hide

import (
	"github.com/zmap/zcrypto/x509"
)

/*
Contains the structs needed to parse the ZGrab Banner Response.
*/

type BannerResult struct {
	Banner string
	Length int
}

type BannerBanner struct {
	Status    string       `json:"status"`
	Protocol  string       `json:"protocol"`
	Result    BannerResult `json:"result"`
	Timestamp string       `json:"timestamp"`
}

type Subject struct {
	Common_Name  []string
	Country      []string
	Organization []string
}

type Issuer struct {
	Common_Name  []string
	Country      []string
	Organization []string
}

type Parsed struct {
	Version            int
	Serial_Number      string
	Issuer             Issuer
	Issuer_DN          string
	Subject            Subject
	Subject_DN         string
	Fingerprint_Md5    string
	Fingerprint_SHA1   string
	Fingerprint_SHA256 string
}

type Certificate struct {
	Raw    []byte `json:"raw,omitempty"`
	Parsed Parsed `json:"parsed,omitempty"`
}

type Server_Certificates struct {
	Certificate Certificate     `json:"certificate"`
	Chain       []Certificate   `json:"chain,omitempty"`
	Validation  x509.Validation `json:"validation,omitempty"`
}
type Handshake_Log struct {
	Server_Certificates Server_Certificates `json:"server_certificates"`
}

type Result struct {
	Handshake_Log Handshake_Log `json:"handshake_log"`
}

type TLS struct {
	Status    string `json:"status"`
	Protocol  string `json:"protocol"`
	Result    Result `json:"result"`
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
}

type JARMResult struct {
	Fingerprint string `json:"fingerprint"`
}

type JARMJARM struct {
	Status    string     `json:"status"`
	Protocol  string     `json:"protocol"`
	Result    JARMResult `json:"result"`
	Error     string     `json:"error"`
	Timestamp string     `json:"timestamp"`
}

type HTTPProtocol struct {
	Name  string
	Major int
	Minor int
}

type HTTPResponse struct {
	Status_Line string       `json:"status_line"`
	Status_Code int          `json:"status_code"`
	Body        string       `json:"body"`
	Body_Sha256 string       `json:"body_sha256"`
	Protocol    HTTPProtocol `json:"protocol"`
	Headers_Raw string       `json:"headers_raw"`
}

type HTTPResult struct {
	Response HTTPResponse `json:"response"`
}

type HTTPHTTP struct {
	Status    string     `json:"status"`
	Protocol  string     `json:"protocol"`
	Result    HTTPResult `json:"result"`
	Error     string     `json:"error"`
	Timestamp string     `json:"timestamp"`
}

type Data struct {
	TLS    TLS          `json:"tls,omitempty"`
	Banner BannerBanner `json:"banner,omitempty"`
	Jarm   JARMJARM     `json:"jarm,omitempty"`
	HTTP   HTTPHTTP     `json:"http,omitempty"`
}

type GeneralResponse struct {
	IP   string `json:"ip"`
	Data Data   `json:"data"`
	Port string
}

type DB_Banner struct {
	Uid           string
	Address       string
	Port          string
	Status        string
	Banner_Hex    string
	Banner_Text   string
	Banner_Length int
	Timestamp     string
}

type DB_TLS struct {
	Uid                  string
	Address              string
	Port                 string
	Status               string
	Timestamp            string
	Version              int
	Serial_Number        string
	Issuer_Common_Name   string
	Issuer_Country       string
	Issuer_Organization  string
	Issuer_DN            string
	Subject_Common_Name  string
	Subject_Country      string
	Subject_Organization string
	Subject_DN           string
	Fingerprint_Md5      string
	Fingerprint_SHA1     string
	Fingerprint_SHA256   string
	JA4X                 string
}

type DB_JARM struct {
	Uid              string
	Address          string
	Port             string
	Status           string
	JARM_Fingerprint string
	Timestamp        string
}

type DB_Gen struct {
	Uid       string
	Address   string
	Port      string
	Timestamp string
}

type DB_HTTP struct {
	Uid           string
	Address       string
	Port          string
	Status        string
	Status_Line   string
	Status_Code   int
	Protocol_Name string
	Headers       string
	Body          string
	Body_SHA256   string
	Timestamp     string
}

// Struct for Hunt IO Certifictes

type HuntIO_Certs struct {
	HashSha256                  string
	HashSha1                    string
	HashMd5                     string
	UUID                        string
	JA4X                        string
	SeenFirst                   string
	SeenLast                    string
	SeenTimes                   int
	Version                     int
	Serial                      string
	NotBefore                   string
	NotAfter                    string
	SubjectCommonName           string
	SubjectCountry              []string
	SubjectOrganization         []string
	SubjectOrganizationalUnit   []string
	SubjectLocality             []string
	SubjectProvince             []string
	SubjectStreetAddress        []string
	SubjectPostalCode           []string
	SubjectSubjectSerialNumber  string
	IssuerCommonName            string
	IssuerCountry               []string
	IssuerOrganization          []string
	IssuerOrganizationalUnit    []string
	IssuerLocality              []string
	IssuerProvince              []string
	IssuerStreetAddress         []string
	IssuerPostalCode            []string
	IssuerSubjectSerialNumber   string
	PolicyIdentifiers           string
	SignatureAlgorithm          string
	UnhandledCriticalExtensions string
	UnknownExtKeyUsage          string
	PrivateKey_BitLength        int
	PrivateKey_Type             string
	KeyUsage                    string
	ExtKeyUsage                 []string
	PermittedDNSDomainsCritical int
	PermittedDNSDomains         []string
	PermittedEmailAddresses     []string
	PermittedURIDomains         []string
	PermittedIPRanges           []string
	ExcludedDNSDomains          []string
	ExcludedEmailAddresses      []string
	ExcludedURIDomains          []string
	ExcludedIPRanges            []string
	BasicConstraintsValid       int
	CRLDistributionPoints       string
	DNSNames                    []string
	EmailAddresses              []string
	IPAddresses                 []string
	URIs                        []string
	IssuingCertificateURL       []string
	IsCA                        int
	MaxPathLen                  int
	MaxPathLenZero              int
	OCSPServer                  []string
	Hostnames                   string
	Scan_Endpoints              []string
}
