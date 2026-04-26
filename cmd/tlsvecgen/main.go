package main

import (
	"flag"
	"log"
	"net/http"
)

var ianaCS, ianaExt, ianaEC, dst string

func init() {
	flag.StringVar(&ianaCS, "cipher-suites", "", "Full URL to IANA source CSV with supported TLS cipher suites.")
	flag.StringVar(&ianaExt, "extensions", "", "Full URL to IANA source CSV with supported TLS extensions.")
	flag.StringVar(&ianaEC, "elliptic-curves", "", "Full URL to IANA source CSV with supported elliptic curves.")
	flag.StringVar(&dst, "dst", "", "Path to destination Go file.")
	flag.Parse()
	if len(ianaCS) == 0 && len(ianaExt) == 0 && len(ianaEC) == 0 {
		log.Fatalln("empty source URL provided")
	}
	if len(dst) == 0 {
		log.Fatalln("empty destination path provided")
	}
}

func main() {
	var ianaURL string
	switch {
	case len(ianaCS) > 0:
		ianaURL = ianaCS
	case len(ianaExt) > 0:
		ianaURL = ianaExt
	case len(ianaEC) > 0:
		ianaURL = ianaEC
	}

	resp, err := http.Get(ianaURL)
	if err != nil {
		log.Fatalln(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var (
		unit string
		c    int
	)
	switch {
	case len(ianaCS) > 0:
		unit = "cipher suites"
		c, err = genCS(resp.Body, dst)
	case len(ianaExt) > 0:
		unit = "extensions"
		c, err = genExt(resp.Body, dst)
	case len(ianaEC) > 0:
		unit = "elliptic curves"
		c, err = genEC(resp.Body, dst)
	}

	if err != nil {
		log.Fatalf("failed %s generation due to error: %s", unit, err.Error())
	}

	log.Printf("%d %s writes to %s\n", c, unit, dst)
}
