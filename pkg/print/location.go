package print

import (
	"fmt"
	"github.com/jonhadfield/certreader/pkg/cert"
	"log/slog"
	"strings"
	"time"
)

func Locations(certificateLocations []cert.CertificateLocation, printChains, printPem, printExtensions, printSignature bool) {

	for _, certificateLocation := range certificateLocations {
		if certificateLocation.Error != nil {
			slog.Error(fmt.Sprintf("%s: %v", certificateLocation.Name(), certificateLocation.Error))
			fmt.Printf("--- [%s: %v] ---\n", certificateLocation.Name(), certificateLocation.Error)
			fmt.Println()
			continue
		}

		fmt.Printf("--- [%s] ---\n", certificateLocation.Name())
		printCertificates(certificateLocation.Certificates, printPem, printExtensions, printSignature)

		if printChains {
			chains, err := certificateLocation.Chains()
			if err != nil {
				slog.Error(fmt.Sprintf("chains for %s: %v", certificateLocation.Name(), certificateLocation.Error))
				fmt.Printf("--- [chains for %s: %v] ---\n", certificateLocation.Name(), err)
				continue
			}

			if len(chains) == 1 {
				fmt.Printf("--- [%d chain for %s] ---\n", len(chains), certificateLocation.Name())
			} else {
				fmt.Printf("--- [%d chains for %s] ---\n", len(chains), certificateLocation.Name())
			}
			for i, chain := range chains {
				fmt.Printf(" -- [chain %d] -- \n", i+1)
				printCertificates(chain, printPem, printExtensions, printSignature)
			}
		}
	}
}

func printCertificates(certs cert.Certificates, printPem, printExtensions, printSignature bool) {

	for _, certificate := range certs {
		printCertificate(certificate, printExtensions, printSignature)
		fmt.Println()
		if printPem {
			fmt.Println(string(certificate.ToPEM()))
		}
	}
}

func printCertificate(certificate cert.Certificate, printExtensions, printSignature bool) {

	if certificate.Error() != nil {
		slog.Error(certificate.Error().Error())
		fmt.Println(certificate.Error())
		return
	}

	fmt.Printf("%s: %d\n", AttributeName("Version"), certificate.Version())
	fmt.Printf("%s: %s\n", AttributeName("Serial Number"), certificate.SerialNumber())
	fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), certificate.SignatureAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Type"), certificate.Type())
	fmt.Printf("%s: %s\n", AttributeName("Issuer"), certificate.Issuer())
	fmt.Printf("%s\n", AttributeName("Validity"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Not Before"), validityFormat(certificate.NotBefore()))
	fmt.Printf("    %s: %s\n", SubAttributeName("Not After"), NotAfterDate(certificate.NotAfter()))
	fmt.Printf("%s: %s\n", AttributeName("Subject"), certificate.SubjectString())
	fmt.Printf("%s: %s\n", AttributeName("DNS Names"), strings.Join(certificate.DNSNames(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("IP Addresses"), strings.Join(certificate.IPAddresses(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Authority Key Id"), certificate.AuthorityKeyId())
	fmt.Printf("%s\n", AttributeName("Subject Key"))
	fmt.Printf("    %s: %s\n", SubAttributeName("Id"), certificate.SubjectKeyId())
	fmt.Printf("    %s: %s\n", SubAttributeName("Algorithm"), certificate.PublicKeyAlgorithm())
	fmt.Printf("%s: %s\n", AttributeName("Key Usage"), strings.Join(certificate.KeyUsage(), ", "))
	fmt.Printf("%s: %s\n", AttributeName("Ext Key Usage"), strings.Join(certificate.ExtKeyUsage(), ", "))
	fmt.Printf("%s: %t\n", AttributeName("CA"), certificate.IsCA())

	if printExtensions {
		fmt.Printf("%s:\n", AttributeName("Extensions"))
		for _, extension := range certificate.Extensions() {
			name := fmt.Sprintf("%s (%s)", extension.Name, extension.Oid)
			if extension.Critical {
				name = fmt.Sprintf("%s [critical]", name)
			}
			fmt.Printf("    %s\n", SubAttributeName(name))
			for _, line := range extension.Values {
				fmt.Printf("        %s\n", line)
			}
		}
	}

	if printSignature {
		fmt.Printf("%s: %s\n", AttributeName("Signature Algorithm"), certificate.SignatureAlgorithm())
		fmt.Printf("%s\n", AttributeName("Signature Value"))
		for _, line := range splitString(certificate.Signature(), "    ", 54) {
			fmt.Println(line)
		}
	}
}

func validityFormat(t time.Time) string {
	// format for NotBefore and NotAfter fields to make output similar to openssl
	return t.Format("Jan _2 15:04:05 2006 MST")
}

func splitString(in, prefix string, size int) []string {
	if len(in) <= size {
		return []string{prefix + in}
	}

	var chunk string
	var out []string
	for {
		in, chunk = in[size:], in[:size]
		out = append(out, prefix+chunk)
		if len(in) <= size {
			out = append(out, prefix+in)
			break
		}
	}
	return out
}
