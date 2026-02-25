package commands

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// enhanceError wraps an error with context and suggestions for common AWS issues.
func enhanceError(action string, err error) error {
	msg := err.Error()

	var hint string
	switch {
	case strings.Contains(msg, "NoCredentialProviders"):
		hint = "Configure AWS credentials: set AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or run 'aws configure'"
	case strings.Contains(msg, "ExpiredToken"):
		hint = "AWS session token expired. Refresh credentials or run 'aws sso login'"
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedAccess"):
		hint = "Insufficient permissions. Apply the IAM policy from 'awsspectre init' to your role/user"
	case strings.Contains(msg, "RequestExpired"):
		hint = "Request expired. Check system clock synchronization"
	case strings.Contains(msg, "Throttling"):
		hint = "AWS API rate limit hit. Retry with fewer regions or increase timeout"
	}

	if hint != "" {
		return fmt.Errorf("%s: %w\n  hint: %s", action, err, hint)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// computeTargetHash generates a SHA256 hash for the target URI.
func computeTargetHash(profile string, regions []string) string {
	input := fmt.Sprintf("profile:%s,regions:%s", profile, strings.Join(regions, ","))
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", h)
}
