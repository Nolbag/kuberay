package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// AuthenticationResourcesCreated means the downstream authentication resources are ready.
	AuthenticationResourcesCreated = "AuthenticationResourcesCreated"
	// AuthenticationDisabled means authentication is disabled for the RayCluster.
	AuthenticationDisabled = "AuthenticationDisabled"
	// AuthenticationFailed means downstream authentication reconciliation failed.
	AuthenticationFailed = "AuthenticationFailed"
)

// GenerateDNS1123Name preserves the downstream route naming contract.
func GenerateDNS1123Name(baseName string) string {
	const maxLen = validation.DNS1123LabelMaxLength
	if len(baseName) <= maxLen {
		return baseName
	}
	hash := sha256.Sum256([]byte(baseName))
	suffix := hex.EncodeToString(hash[:])[:10]
	suffixLen := len(suffix) + 1
	maxPrefixLen := maxLen - suffixLen
	prefix := strings.TrimRight(baseName[:maxPrefixLen], "-")
	return prefix + "-" + suffix
}
