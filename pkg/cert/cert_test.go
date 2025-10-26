package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestFromBytes(t *testing.T) {
	t.Run("given valid PEM certificate, then certificate is loaded", func(t *testing.T) {
		certificates := loadTestCertificates(t, "cert.pem")
		require.Equal(t, 1, len(certificates))
		assert.Equal(t, 1, certificates[0].position)
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", certificates[0].SubjectString())
		assert.Nil(t, certificates[0].err)
	})

	t.Run("given valid PEM bundle, then all certificates are loaded", func(t *testing.T) {
		certificates := loadTestCertificates(t, "bundle.pem")
		require.Equal(t, 2, len(certificates))
		assert.Equal(t, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US", certificates[0].SubjectString())
		assert.Equal(t, "CN=GTS Root R1,O=Google Trust Services LLC,C=US", certificates[1].SubjectString())
	})

	t.Run("given PKCS12 certificate with password, then certificate is loaded", func(t *testing.T) {
		pfx := newPKCS12Bundle(t, "password123")
		certificates, err := FromBytes(pfx, "password123")
		require.NoError(t, err)
		require.Len(t, certificates, 1)
		assert.Equal(t, "CN=certreader pkcs12 test", certificates[0].SubjectString())
	})

	t.Run("given PKCS12 certificate without password, then certificate is loaded", func(t *testing.T) {
		pfx := newPKCS12Bundle(t, "")
		certificates, err := FromBytes(pfx, "")
		require.NoError(t, err)
		require.Len(t, certificates, 1)
		assert.Equal(t, "CN=certreader pkcs12 test", certificates[0].SubjectString())
	})

	t.Run("given PKCS12 certificate requiring password and none supplied, then error is returned", func(t *testing.T) {
		pfx := newPKCS12Bundle(t, "topsecret")
		_, err := FromBytes(pfx, "")
		var pwErr *PasswordRequiredError
		require.ErrorAs(t, err, &pwErr)
		require.NotNil(t, pwErr)
		assert.False(t, pwErr.Provided())
	})

	t.Run("given PKCS12 certificate with wrong password, then prompt error is returned", func(t *testing.T) {
		pfx := newPKCS12Bundle(t, "topsecret")
		_, err := FromBytes(pfx, "badpassword")
		var pwErr *PasswordRequiredError
		require.ErrorAs(t, err, &pwErr)
		require.NotNil(t, pwErr)
		assert.True(t, pwErr.Provided())
	})
}

func TestCertificates_RemoveDuplicates(t *testing.T) {
	t.Run("given duplicate PEM certificate, when remove duplicates is called, then they are removed", func(t *testing.T) {
		certificates := loadTestCertificates(t, "bundle.pem", "bundle.pem")

		require.Equal(t, 4, len(certificates))
		noDuplicates := certificates.RemoveDuplicates()
		require.Equal(t, 2, len(noDuplicates))
	})
}

func TestCertificates_SortByExpiry(t *testing.T) {
	t.Run("given multiple certificates, when they have different expiry, then they are sorted", func(t *testing.T) {
		certificates := Certificates{
			// using version to validate tests
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(0, 6, 3), Version: 1}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 2), Version: 3}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 6, 21), Version: 4}},
			{x509Certificate: &x509.Certificate{NotAfter: time.Now().AddDate(1, 3, 3), Version: 2}},
		}

		sortedCertificates := certificates.SortByExpiry()
		require.Equal(t, 4, len(sortedCertificates))
		assert.Equal(t, 1, sortedCertificates[0].x509Certificate.Version)
		assert.Equal(t, 2, sortedCertificates[1].x509Certificate.Version)
		assert.Equal(t, 3, sortedCertificates[2].x509Certificate.Version)
		assert.Equal(t, 4, sortedCertificates[3].x509Certificate.Version)
	})
}

func Test_rootIdentification(t *testing.T) {
	t.Run("given certificate issuer is identical to subject but authority key id is set then identify as root", func(t *testing.T) {
		certificate := loadTestCertificates(t, "root_with_authority_key_id.pem")
		require.Len(t, certificate, 1)
		require.Equal(t, certificate[0].x509Certificate.RawSubject, certificate[0].x509Certificate.RawIssuer)
		require.NotEmpty(t, certificate[0].x509Certificate.AuthorityKeyId)
		require.Equal(t, "root", certificate[0].Type())
	})

	t.Run("given certificate authority key id is unset then identify as root", func(t *testing.T) {
		certificate := loadTestCertificates(t, "cert.pem")
		require.Len(t, certificate, 1)
		assert.Len(t, certificate[0].x509Certificate.AuthorityKeyId, 0)
		assert.True(t, certificate[0].x509Certificate.IsCA)
		require.Equal(t, "root", certificate[0].Type())
	})
}

func Test_intermediateIdentification(t *testing.T) {
	t.Run("given intermediate certificate issuer is identical to subject but authority and subject keys are different then identify as intermediate", func(t *testing.T) {
		certificate := loadTestCertificates(t, "intermediate_same_issuer_and_subject.pem")
		require.Len(t, certificate, 1)
		require.Equal(t, certificate[0].x509Certificate.RawSubject, certificate[0].x509Certificate.RawIssuer)
		require.NotEmpty(t, certificate[0].x509Certificate.AuthorityKeyId)
		require.Equal(t, "intermediate", certificate[0].Type())
	})
}

func newPKCS12Bundle(t *testing.T, password string) []byte {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certreader pkcs12 test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	enc := pkcs12.Modern2023
	if password == "" {
		enc = pkcs12.Passwordless
	}
	pfx, err := enc.Encode(privKey, cert, nil, password)
	require.NoError(t, err)
	return pfx
}
