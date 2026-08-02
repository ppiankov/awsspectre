package report

import (
	"testing"

	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

// allFindingIDs mirrors the full FindingID const block in internal/aws/types.go.
// WO-225 found buildSARIFRules() silently missing entries for two new finding
// IDs — a real GitHub Code Scanning consumer would see result ruleIds not
// declared in tool.driver.rules[]. This test closes that gap structurally:
// every FindingID must have a declared SARIF rule, checked here rather than
// relying on each future WO to remember to update sarif.go by hand.
var allFindingIDs = []awstype.FindingID{
	awstype.FindingIdleEC2,
	awstype.FindingStoppedEC2,
	awstype.FindingDetachedEBS,
	awstype.FindingUnusedEIP,
	awstype.FindingIdleALB,
	awstype.FindingIdleNLB,
	awstype.FindingIdleNATGateway,
	awstype.FindingLowTrafficNATGateway,
	awstype.FindingIdleRDS,
	awstype.FindingStaleSnapshot,
	awstype.FindingUnusedSecurityGroup,
	awstype.FindingIdleLambda,
	awstype.FindingKinesisStreamIdle,
	awstype.FindingKinesisOverProvisioned,
	awstype.FindingKinesisFirehoseIdle,
	awstype.FindingSQSIdle,
	awstype.FindingSQSDLQOrphaned,
	awstype.FindingSQSNoConsumer,
	awstype.FindingSNSNoSubscribers,
	awstype.FindingSNSIdle,
	awstype.FindingCloudFrontDisabled,
	awstype.FindingCloudFrontIdle,
	awstype.FindingLogGroupNoRetention,
	awstype.FindingGP2MigrationCandidate,
	awstype.FindingECRNoLifecyclePolicy,
	awstype.FindingECRUntaggedImageSprawl,
}

func TestBuildSARIFRules_DeclaresEveryFindingID(t *testing.T) {
	rules := buildSARIFRules()
	declared := make(map[string]bool, len(rules))
	for _, r := range rules {
		declared[r.ID] = true
	}

	for _, id := range allFindingIDs {
		if !declared[string(id)] {
			t.Errorf("FindingID %s has no declared SARIF rule in buildSARIFRules()", id)
		}
	}
}

func TestBuildSARIFRules_NoDuplicateIDs(t *testing.T) {
	rules := buildSARIFRules()
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate SARIF rule ID: %s", r.ID)
		}
		seen[r.ID] = true
	}
}
