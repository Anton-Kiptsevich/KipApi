package utils

import (
	"regexp"
	"strings"
)

func GetAllSignaturePlaceholders(signature string) []string {
	return regexp.MustCompile(`\{([^{}]+)\}`).FindAllString(signature, -1)
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
