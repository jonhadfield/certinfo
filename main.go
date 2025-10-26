package main

import (
	"errors"
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"github.com/jonhadfield/certreader/pkg/print"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/term"
)

var Version = "dev"

func main() {

	flags, err := ParseFlags()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	setLogger(flags.Verbose)

	if flags.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	certificatesFiles := LoadCertificatesLocations(flags)
	if flags.NoExpired {
		certificatesFiles = certificatesFiles.RemoveExpired()
	}
	if flags.NoDuplicate {
		certificatesFiles = certificatesFiles.RemoveDuplicates()
	}
	if flags.SubjectLike != "" {
		certificatesFiles = certificatesFiles.SubjectLike(flags.SubjectLike)
	}
	if flags.IssuerLike != "" {
		certificatesFiles = certificatesFiles.IssuerLike(flags.IssuerLike)
	}
	if flags.SortExpiry {
		certificatesFiles = certificatesFiles.SortByExpiry()
	}
	if flags.Expiry {
		print.Expiry(certificatesFiles)
		return
	}
	if flags.PemOnly {
		print.Pem(certificatesFiles, flags.Chains)
		return
	}
	print.Locations(certificatesFiles, flags.Chains, flags.Pem, flags.Extensions, flags.Signature)
}

func setLogger(verbose bool) {
	level := slog.LevelError
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func LoadCertificatesLocations(flags Flags) cert.CertificateLocations {

	var certificateLocations cert.CertificateLocations
	if flags.Clipboard {
		certificateLocations = append(certificateLocations, cert.LoadCertificateFromClipboard(flags.PfxPassword))
	}

	if len(flags.Args) > 0 {
		certificateLocations = append(certificateLocations, loadFromArgs(flags.Args, flags.ServerName, flags.Insecure, flags.PfxPassword)...)
	}

	if isStdin() {
		certificateLocations = append(certificateLocations, cert.LoadCertificateFromStdin(flags.PfxPassword))
	}

	certificateLocations = maybePromptForPFXPasswords(certificateLocations, &flags)

	if len(certificateLocations) > 0 {
		return certificateLocations
	}

	// no stdin and no args
	flags.Usage()
	os.Exit(0)
	return nil
}

func loadFromArgs(args []string, serverName string, insecure bool, password string) cert.CertificateLocations {

	out := make(chan cert.CertificateLocation)
	go func() {
		var wg sync.WaitGroup
		for _, arg := range args {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if isTCPNetworkAddress(arg) {
					out <- cert.LoadCertificatesFromNetwork(arg, serverName, insecure)
					return
				}
				out <- cert.LoadCertificatesFromFile(arg, password)
			}()
		}
		wg.Wait()
		close(out)
	}()

	// load certificates from the channel
	certsByArgs := make(map[string]cert.CertificateLocation)
	for location := range out {
		certsByArgs[location.Path] = location
	}

	// sort certificates by input arguments
	var certsSortedByArgs cert.CertificateLocations
	for _, arg := range args {
		certsSortedByArgs = append(certsSortedByArgs, certsByArgs[arg])
	}
	return certsSortedByArgs
}

func maybePromptForPFXPasswords(locations cert.CertificateLocations, flags *Flags) cert.CertificateLocations {
	for i := range locations {
		var pwErr *cert.PasswordRequiredError
		if !errors.As(locations[i].Error, &pwErr) {
			continue
		}
		if pwErr == nil || pwErr.Data() == nil {
			continue
		}

		// Reattempt automatically if a new password has been supplied since initial load
		if flags.PfxPassword != "" {
			updated := reloadWithPassword(locations[i], pwErr, flags.PfxPassword)
			if updated.Error == nil {
				locations[i] = updated
				continue
			}
			var newPwErr *cert.PasswordRequiredError
			if errors.As(updated.Error, &newPwErr) {
				pwErr = newPwErr
			} else {
				locations[i] = updated
				continue
			}
		}

		if !canPromptForPassword() {
			continue
		}

		fmt.Fprintf(os.Stderr, "%s requires a password.\n", promptLabel(locations[i].Path))
		for attempt := 0; attempt < 3; attempt++ {
			password, ok := promptForPasswordInput(locations[i].Path, attempt)
			if !ok {
				break
			}
			if password == "" {
				fmt.Fprintln(os.Stderr, "No password entered; leaving certificate unresolved.")
				break
			}
			updated := reloadWithPassword(locations[i], pwErr, password)
			if updated.Error == nil {
				locations[i] = updated
				flags.PfxPassword = password
				break
			}
			var newPwErr *cert.PasswordRequiredError
			if errors.As(updated.Error, &newPwErr) {
				pwErr = newPwErr
				fmt.Fprintln(os.Stderr, "Password incorrect; try again.")
				continue
			}
			locations[i] = updated
			break
		}
	}
	return locations
}

func reloadWithPassword(location cert.CertificateLocation, pwErr *cert.PasswordRequiredError, password string) cert.CertificateLocation {
	certificates, err := cert.FromBytes(pwErr.Data(), password)
	if err != nil {
		var newPwErr *cert.PasswordRequiredError
		if errors.As(err, &newPwErr) {
			newPwErr.SetSource(pwErr.Source())
		}
		return cert.CertificateLocation{
			Path:       location.Path,
			TLSVersion: location.TLSVersion,
			Error:      err,
		}
	}
	return cert.CertificateLocation{
		Path:         location.Path,
		TLSVersion:   location.TLSVersion,
		Certificates: certificates,
	}
}

func promptLabel(path string) string {
	switch path {
	case "stdin":
		return "stdin"
	case "clipboard":
		return "clipboard"
	default:
		return path
	}
}

func canPromptForPassword() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

func promptForPasswordInput(path string, attempt int) (string, bool) {
	prompt := fmt.Sprintf("Enter password for %s", promptLabel(path))
	if attempt > 0 {
		prompt += " (try again)"
	}
	prompt += ": "
	fmt.Fprint(os.Stderr, prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		slog.Error("reading password", slog.String("path", path), slog.Any("err", err))
		return "", false
	}
	return strings.TrimSpace(string(passwordBytes)), true
}

func isTCPNetworkAddress(arg string) bool {

	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return false
	}
	return true
}

func isStdin() bool {

	info, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("checking stdin: %v\n", err)
		return false
	}

	if (info.Mode() & os.ModeCharDevice) == 0 {
		return true
	}
	return false
}
