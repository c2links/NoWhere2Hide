package utils

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"gopkg.in/yaml.v2"
)

// Struct for extracting API Keys
type API_KEYS struct {
	CENSYS_API_ID string
	CENSYS_SECRET string
	SHODAN        string
}

/*
This function takes an ASN and returns the IP Ranges associated with the ASN.
The IP range data is pulled from this Github resource, https://raw.githubusercontent.com/ipverse/asn-ip/

Input: asn number (no AS prefix)
Output: slice of IP ranges for that ASN
*/

func ASN2CIDR(asn int) ([]string, error) {

	// String slice container to hold results
	var ipRange []string

	//Pulls the ASN information from https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%s/ipv4-aggregated.txt
	url := fmt.Sprintf("https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%s/ipv4-aggregated.txt", strconv.FormatInt(int64(asn), 10))

	//Open HTTP Client
	http_client := http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		r.URL.Opaque = r.URL.Path
		return nil
	},
	}

	//Get the ASN info from IPVerse
	resp, err := http_client.Get(url)
	if err != nil {
		return ipRange, err
	}

	//Save the response to string variable
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ipRange, err
	}

	/* The response from IPVerse looks like the below.

			# AS1234 (FORTUM)
			# Fortum
			#
			132.171.0.0/16
			137.96.0.0/16
			193.110.32.0/21

	The below code, skips any lines that start with the # character and adds the other lines
	to the result slice. This assumes that all lines without a # character are the IP ranges. Which I have not
	seen otherwise.
	*/

	lines := strings.Split(string(body), "\n")

	for _, v := range lines {

		if !strings.HasPrefix(v, "#") {
			ipRange = append(ipRange, v)
		}
	}

	//return IP Range Slice
	return ipRange, nil

}

/*
This function takes a CIDR range and populates a slice with all the IP addresses
in that range.
*/

func CIDR2IP(cidr string) ([]string, error) {

	var ips []string

	p, err := netip.ParsePrefix(cidr)

	if err != nil {
		return ips, err
	}
	p = p.Masked()
	addr := p.Addr()
	for {
		if !p.Contains(addr) {
			break
		}
		ips = append(ips, addr.String())
		addr = addr.Next()
	}

	return ips, err
}

/*
This function loads the API keys located in api.yaml file
*/

func LoadAPI() (API_KEYS, error) {

	var api_keys API_KEYS

	data, err := os.ReadFile("../api.yaml")
	if err != nil {
		return api_keys, err
	}

	err = yaml.Unmarshal(data, &api_keys)
	if err != nil {
		return api_keys, err
	}

	return api_keys, err
}

/*
This function dedupes a string slice. Used mostly to dedupe IPs and Ports
*/

func DedupeStringSlice(s []string) []string {
	inResult := make(map[string]bool)
	var result []string
	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}
	return result
}

/*
This function creates a MD% hash of a input string
*/

func GetMD5Hash(text string) string {

	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

/*
Function to pull a file from a Github Repo. It is used to pull the ASN port scans for the Bad ASN scanning
*/
func GetFile(ctx context.Context, owner string, repo string, branch string, filename string) (string, error) {
	// Clone the remote git repository

	r, err := git.PlainCloneContext(ctx, repo, false, &git.CloneOptions{
		URL: fmt.Sprintf("https://github.com/%s/%s.git", owner, repo),
	})

	if err != nil {
		return "", fmt.Errorf("failed to clone repository: %w", err)

	}

	// Checkout the specified branch
	w, err := r.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree: %w", err)
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch)),
	})

	if err != nil {
		return "", fmt.Errorf("failed to checkout branch: %w", err)
	}

	// Read the content of the file
	filePath := fmt.Sprintf("%s/%s", repo, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	os.RemoveAll(repo)
	return string(content), nil
}
