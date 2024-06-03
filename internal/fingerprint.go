package subjack

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/haccer/available"
)

type Fingerprints struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
}

/*
* Triage step to check whether the CNAME matches
* the fingerprinted CNAME of a vulnerable cloud service.
 */
func VerifyCNAME(subdomain string, config []Fingerprints) (match bool) {
	cname := resolve(subdomain)
	match = false

VERIFY:
	for n := range config {
		for c := range config[n].Cname {
			if strings.Contains(cname, config[n].Cname[c]) {
				match = true
				break VERIFY
			}
		}
	}

	return match
}

func detect(url, output string, ssl, verbose, manual bool, timeout int, config []Fingerprints) {
	service := Identify(url, ssl, manual, timeout, config)

	if service != "" {
		result := fmt.Sprintf("[VULNERABLE:%s] %s\n", service, url)
		fmt.Print(result)

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}

	if service == "" && verbose {
		result := fmt.Sprintf("[NOT_VULNERABLE] %s\n", url)
		fmt.Print(result)

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}
}

/*
* This function aims to identify whether the subdomain
* is attached to a vulnerable cloud service and able to
* be taken over.
 */
func Identify(subdomain string, forceSSL, manual bool, timeout int, fingerprints []Fingerprints) (service string) {
	body := get(subdomain, forceSSL, timeout)

	cname := resolve(subdomain)

	if len(cname) <= 3 {
		cname = ""
	}

	service = ""
	nx := nxdomain(subdomain)

IDENTIFY:
	for f := range fingerprints {

		// Begin subdomain checks if the subdomain returns NXDOMAIN
		if nx {

			// Check if we can register this domain.
			dead := available.Domain(cname)
			if dead {
				service = "DOMAIN_AVAILABLE:" + cname
				break IDENTIFY
			}

			// Check if subdomain matches fingerprinted cname
			if fingerprints[f].Nxdomain {
				for n := range fingerprints[f].Cname {
					if strings.Contains(cname, fingerprints[f].Cname[n]) {
						service = strings.ToUpper(fingerprints[f].Service)
						break IDENTIFY
					}
				}
			}

			// Option to always print the CNAME and not check if it's available to be registered.
			if manual && !dead && cname != "" {
				service = "DOMAIN_DEAD:" + cname
				break IDENTIFY
			}
		}

		// Check if body matches fingerprinted response
		for n := range fingerprints[f].Fingerprint {
			if bytes.Contains(body, []byte(fingerprints[f].Fingerprint[n])) {
				service = strings.ToUpper(fingerprints[f].Service)
				break
			}
		}
	}

	return service
}
