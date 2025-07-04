package util

import "strings"

func AllToLower(list []string) []string {
	lower := make([]string, len(list))

	for i, elem := range list {
		lower[i] = strings.ToLower(elem)
	}

	return lower
}

func AllToUpper(list []string) []string {
	upper := make([]string, len(list))

	for i, elem := range list {
		upper[i] = strings.ToUpper(elem)
	}

	return upper
}
