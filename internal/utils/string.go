package utils

import "regexp"

func GetAllSignaturePlaceholders(signature string) []string {
	return regexp.MustCompile(`\{([^{}]+)\}`).FindAllString(signature, -1)
}