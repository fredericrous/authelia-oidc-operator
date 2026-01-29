package v1alpha1

import "strings"

// hyphenToUnderscore converts Kubernetes naming convention (hyphens) to Authelia naming convention (underscores)
func hyphenToUnderscore(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}
