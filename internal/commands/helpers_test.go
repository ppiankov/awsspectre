package commands

import (
	"fmt"
	"strings"
	"testing"
)

func TestEnhanceError_NoCredentials(t *testing.T) {
	err := enhanceError("test", fmt.Errorf("NoCredentialProviders: no valid providers"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for NoCredentialProviders")
	}
	if !strings.Contains(err.Error(), "AWS_PROFILE") {
		t.Fatal("expected hint to mention AWS_PROFILE")
	}
}

func TestEnhanceError_ExpiredToken(t *testing.T) {
	err := enhanceError("test", fmt.Errorf("ExpiredToken: token has expired"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for ExpiredToken")
	}
}

func TestEnhanceError_AccessDenied(t *testing.T) {
	err := enhanceError("test", fmt.Errorf("AccessDenied: not authorized"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for AccessDenied")
	}
}

func TestEnhanceError_Throttling(t *testing.T) {
	err := enhanceError("test", fmt.Errorf("Throttling: rate exceeded"))
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected hint for Throttling")
	}
}

func TestEnhanceError_GenericError(t *testing.T) {
	err := enhanceError("do something", fmt.Errorf("random error"))
	if strings.Contains(err.Error(), "hint:") {
		t.Fatal("expected no hint for generic error")
	}
	if !strings.Contains(err.Error(), "do something") {
		t.Fatal("expected action in error message")
	}
}

func TestComputeTargetHash(t *testing.T) {
	hash1 := computeTargetHash("prod", []string{"us-east-1", "eu-west-1"})
	hash2 := computeTargetHash("prod", []string{"us-east-1", "eu-west-1"})
	hash3 := computeTargetHash("staging", []string{"us-east-1"})

	if hash1 != hash2 {
		t.Fatal("same input should produce same hash")
	}
	if hash1 == hash3 {
		t.Fatal("different input should produce different hash")
	}
	if !strings.HasPrefix(hash1, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", hash1)
	}
}
