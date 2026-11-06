package utils

import (
	"regexp"
	"strings"

	"github.com/Anton-Kiptsevich/KipApi/constants"
)

const hexDigits = "0123456789ABCDEF"

func GetHexDigits() string {
	return hexDigits
}

func GetTimeFormatPattern() string {
	return "20060102T150405Z"
}

func GetDateFormatPattern() string {
	return "20060102"
}

func IsHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func GetAllSignaturePlaceholders(signature string) []string {
	return regexp.MustCompile(constants.SP_REGEXP_PATTERN).FindAllString(signature, -1)
}

func GetHeaderNameFromPlaceholder(placeholder string) string {
	if !strings.HasPrefix(placeholder, "{header:") || !strings.HasSuffix(placeholder, "}") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(placeholder, "{header:"), "}")
}

func ReplaceHeaderNameWithWildcard(placeholder string) string {
	if !strings.HasPrefix(placeholder, "{header:") || !strings.HasSuffix(placeholder, "}") {
		return placeholder
	}
	return "{header:##}"
}
