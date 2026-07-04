package commands

import (
	"encoding/json"
	"testing"
)

type samplePolicyDocument struct {
	Statement []struct {
		Action []string `json:"Action"`
	} `json:"Statement"`
}

func TestSampleIAMPolicyIncludesCloudFrontScanPermissions(t *testing.T) {
	var policy samplePolicyDocument
	if err := json.Unmarshal([]byte(sampleIAMPolicy), &policy); err != nil {
		t.Fatalf("unmarshal sample IAM policy: %v", err)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("expected one IAM policy statement, got %d", len(policy.Statement))
	}

	actions := make(map[string]bool, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		actions[action] = true
	}

	// WO-199: CloudFront scanner uses this global read action.
	if !actions["cloudfront:ListDistributions"] {
		t.Fatal("expected sample IAM policy to include cloudfront:ListDistributions")
	}
}
