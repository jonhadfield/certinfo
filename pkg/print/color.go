package print

import (
	"github.com/fatih/color"
	"os"
	"time"
)

var (
	// Attribute level colors
	attributeColor    = color.New(color.FgBlue).SprintFunc()
	subAttributeColor = color.New(color.FgCyan).SprintFunc()

	// Date status colors
	validDateColor    = color.New(color.FgGreen).SprintFunc()
	expiringDateColor = color.New(color.FgYellow).SprintFunc()
	expiredDateColor  = color.New(color.FgRed).SprintFunc()
	expiredLabelColor = color.New(color.FgRed, color.Bold).SprintFunc()
)

func init() {
	// Disable colors if not outputting to a terminal
	if !isTerminal() {
		color.NoColor = true
	}
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// AttributeName colorizes a top-level attribute name (Blue)
func AttributeName(name string) string {
	return attributeColor(name)
}

// SubAttributeName colorizes a sub-attribute name (Cyan)
func SubAttributeName(name string) string {
	return subAttributeColor(name)
}

// NotAfterDate colorizes the "Not After" date based on expiry status
// Green: > 30 days until expiry
// Orange/Yellow: <= 30 days until expiry
// Red: expired
func NotAfterDate(t time.Time) string {
	now := time.Now()
	daysUntilExpiry := int(t.Sub(now).Hours() / 24)

	dateStr := validityFormat(t)

	if t.Before(now) {
		// Expired - Red
		return expiredDateColor(dateStr)
	} else if daysUntilExpiry <= 30 {
		// Expiring soon - Yellow/Orange
		return expiringDateColor(dateStr)
	}
	// Valid - Green
	return validDateColor(dateStr)
}

// ExpiryStatus colorizes expiry status messages
func ExpiryStatus(isExpired bool, message string) string {
	if isExpired {
		return expiredLabelColor(message)
	}
	return message
}

// ExpiryMessage colorizes expiry time messages based on days remaining
func ExpiryMessage(daysRemaining int, message string) string {
	if daysRemaining <= 30 {
		return expiringDateColor(message)
	}
	return validDateColor(message)
}
