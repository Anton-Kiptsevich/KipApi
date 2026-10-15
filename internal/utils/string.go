package utils

import (
	"regexp"
	"strings"

	"github.com/Anton-Kiptsevich/KipApi/constants"
)

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
