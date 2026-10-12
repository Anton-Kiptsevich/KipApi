package utils

import (
	"regexp"
	"strings"
)

func GetAllSignaturePlaceholders(signature string) []string {
	return regexp.MustCompile(`\{([^{}]+)\}`).FindAllString(signature, -1)
}

// normalizePlaceholder replaces the wildcard value after the first colon
// with ##, allowing wildcard placeholders to use the same constant-based
// validation as fixed placeholders.
func NormalizePlaceholder(placeholder string) string {
	colon := strings.IndexByte(placeholder, ':')
	if colon == -1 || !strings.HasSuffix(placeholder, "}") {
		return placeholder
	}
	return placeholder[:colon+1] + "##}"
}