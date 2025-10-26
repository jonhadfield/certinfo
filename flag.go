package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"golang.design/x/clipboard"
)

type Flags struct {
	Usage       func()
	Expiry      bool
	NoDuplicate bool
	NoExpired   bool
	SortExpiry  bool
	SubjectLike string
	IssuerLike  string
	ServerName  string
	Insecure    bool
	Chains      bool
	Extensions  bool
	Signature   bool
	Pem         bool
	PemOnly     bool
	Verbose     bool
	Version     bool
	More        bool
	Clipboard   bool
	PfxPassword string
	Args        []string
}

func ParseFlags() (Flags, error) {

	var flags Flags
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.BoolVar(&flags.Expiry, "expiry", getBoolEnv("CERTREADER_EXPIRY", false),
		"print expiry of certificates")
	flagSet.BoolVar(&flags.NoDuplicate, "no-duplicate", getBoolEnv("CERTREADER_NO_DUPLICATE", false),
		"do not print duplicate certificates")
	flagSet.BoolVar(&flags.NoExpired, "no-expired", getBoolEnv("CERTREADER_NO_EXPIRED", false),
		"do not print expired certificates")
	flagSet.BoolVar(&flags.SortExpiry, "sort-expiry", getBoolEnv("CERTREADER_SORT_EXPIRY", false),
		"sort certificates by expiration date")
	flagSet.StringVar(&flags.SubjectLike, "subject-like", getStringEnv("CERTREADER_SUBJECT_LIKE", ""),
		"print certificates with issuer field containing supplied string")
	flagSet.StringVar(&flags.IssuerLike, "issuer-like", getStringEnv("CERTREADER_ISSUER_LIKE", ""),
		"print certificates with subject field containing supplied string")
	flagSet.StringVar(&flags.ServerName, "server-name", getStringEnv("CERTREADER_SERVER_NAME", ""),
		"verify the hostname on the returned certificates, useful for testing SNI")
	flagSet.BoolVar(&flags.Insecure, "insecure", getBoolEnv("CERTREADER_INSECURE", false),
		"whether a client verifies the server's certificate chain and host name (only applicable for host)")
	flagSet.BoolVar(&flags.Chains, "chains", getBoolEnv("CERTREADER_CHAINS", false),
		"whether to print verified chains as well (only applicable for host)")
	flagSet.BoolVar(&flags.Extensions, "extensions", getBoolEnv("CERTREADER_EXTENSIONS", false),
		"whether to print extensions")
	flagSet.BoolVar(&flags.Signature, "signature", getBoolEnv("CERTREADER_SIGNATURE", false),
		"whether to print signature")
	flagSet.BoolVar(&flags.Pem, "pem", getBoolEnv("CERTREADER_PEM", false),
		"whether to print pem as well")
	flagSet.BoolVar(&flags.PemOnly, "pem-only", getBoolEnv("CERTREADER_PEM_ONLY", false),
		"whether to print only pem (useful for downloading certs from host)")
	flagSet.StringVar(&flags.PfxPassword, "pfx-password", getStringEnv("CERTREADER_PFX_PASSWORD", ""),
		"password for PKCS#12/PFX bundles (defaults to empty)")
	if isClipboardSupported() {
		flagSet.BoolVar(&flags.Clipboard, "clipboard", false,
			"read input from clipboard")
	}
	flagSet.BoolVar(&flags.Verbose, "verbose", getBoolEnv("CERTREADER_VERBOSE", false),
		"verbose logging")
	flagSet.BoolVar(&flags.Version, "version", getBoolEnv("CERTREADER_VERSION", false),
		"certreader version")
	flagSet.BoolVar(&flags.More, "more", getBoolEnv("CERTREADER_MORE", false), "combination of '-pem -signature -chains'")

	flagSet.Usage = func() {
		fmt.Fprint(flagSet.Output(), "Usage: certreader [flags] [<file>|<host:port> ...]\n")
		flagSet.PrintDefaults()
	}
	flags.Usage = flagSet.Usage

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return Flags{}, err
	}
	flags.Args = flagSet.Args()

	// Combination of flags
	if flags.More {
		flags.Pem = true
		flags.Signature = true
		flags.Chains = true
	}

	return flags, nil
}

func getStringEnv(envName string, defaultValue string) string {

	if env, ok := os.LookupEnv(envName); ok {
		return env
	}
	return defaultValue
}

func getBoolEnv(envName string, defaultValue bool) bool {

	env, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}

	if intValue, err := strconv.ParseBool(env); err == nil {
		return intValue
	}
	return defaultValue
}

func isClipboardSupported() (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			ok = false
		}
	}()
	return clipboard.Init() == nil
}
