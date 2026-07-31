package aws

import (
	"encoding/json"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func TestFinding_JSON(t *testing.T) {
	f := Finding{
		ID:                    FindingIdleEC2,
		Severity:              SeverityHigh,
		ResourceType:          ResourceEC2,
		ResourceID:            "i-0abc123",
		ResourceName:          "web-server-1",
		Region:                "us-east-1",
		Message:               "CPU 2.1% over 7 days",
		EstimatedMonthlyWaste: 45.50,
		Metadata: map[string]any{
			"instance_type":   "t3.large",
			"avg_cpu_percent": 2.1,
		},
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != FindingIdleEC2 {
		t.Fatalf("expected ID %s, got %s", FindingIdleEC2, decoded.ID)
	}
	if decoded.Severity != SeverityHigh {
		t.Fatalf("expected severity %s, got %s", SeverityHigh, decoded.Severity)
	}
	if decoded.ResourceID != "i-0abc123" {
		t.Fatalf("expected resource_id i-0abc123, got %s", decoded.ResourceID)
	}
	if decoded.EstimatedMonthlyWaste != 45.50 {
		t.Fatalf("expected waste 45.50, got %f", decoded.EstimatedMonthlyWaste)
	}
}

func TestScanResult_JSON(t *testing.T) {
	r := ScanResult{
		Findings: []Finding{
			{
				ID:           FindingUnusedEIP,
				Severity:     SeverityMedium,
				ResourceType: ResourceEIP,
				ResourceID:   "eipalloc-abc123",
				Region:       "us-west-2",
				Message:      "Not associated",
			},
		},
		ResourcesScanned: 10,
		RegionsScanned:   2,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
	if decoded.ResourcesScanned != 10 {
		t.Fatalf("expected 10 resources scanned, got %d", decoded.ResourcesScanned)
	}
}

func TestFinding_NoMetadata(t *testing.T) {
	f := Finding{
		ID:           FindingDetachedEBS,
		Severity:     SeverityHigh,
		ResourceType: ResourceEBS,
		ResourceID:   "vol-abc123",
		Region:       "eu-west-1",
		Message:      "Detached for 14 days",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// metadata should be omitted when nil
	str := string(data)
	if contains(str, "metadata") {
		t.Fatal("expected metadata to be omitted when nil")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFinding_MarshalJSON_DefaultsRemediationPathToDirect(t *testing.T) {
	// WO-228: a finding with no explicit RemediationPath must serialize with
	// remediation_path="direct" rather than an empty string, so consumers
	// (SpectreHub, a CI gate, a dashboard) always get an explicit,
	// machine-readable value without needing to special-case emptiness.
	f := Finding{
		ID:           FindingIdleEC2,
		Severity:     SeverityHigh,
		ResourceType: ResourceEC2,
		ResourceID:   "i-0abc123",
		Region:       "us-east-1",
		Message:      "CPU 2.1% over 7 days",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["remediation_path"] != "direct" {
		t.Fatalf("expected remediation_path=\"direct\", got %v", decoded["remediation_path"])
	}
}

func TestFinding_MarshalJSON_PreservesExplicitRemediationPath(t *testing.T) {
	f := Finding{
		ID:              FindingIdleALB,
		Severity:        SeverityMedium,
		ResourceType:    ResourceALB,
		ResourceID:      "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/k8s-svc/abc",
		Region:          "us-east-1",
		Message:         "managed by a Kubernetes Service/Ingress controller",
		RemediationPath: RemediationViaController,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["remediation_path"] != "via_controller" {
		t.Fatalf("expected remediation_path=\"via_controller\", got %v", decoded["remediation_path"])
	}
}

func TestFinding_UnmarshalOldJSON_NoRemediationPathKey(t *testing.T) {
	// WO-228 is additive: a hand-written JSON fixture with no remediation_path
	// key at all (simulating output from a version before this WO shipped)
	// must decode cleanly, with RemediationPath resolving to the safe default
	// rather than erroring or leaving an ambiguous state.
	oldJSON := `{"id":"IDLE_EC2","severity":"high","resource_type":"ec2","resource_id":"i-1","region":"us-east-1","message":"x"}`

	var decoded Finding
	if err := json.Unmarshal([]byte(oldJSON), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RemediationPath != "" {
		t.Fatalf("expected empty RemediationPath for JSON with no remediation_path key, got %q", decoded.RemediationPath)
	}
	if got := decoded.EffectiveRemediationPath(); got != RemediationDirect {
		t.Fatalf("expected EffectiveRemediationPath to resolve to direct, got %q", got)
	}
}

func TestFinding_EffectiveRemediationPath(t *testing.T) {
	direct := Finding{}
	if got := direct.EffectiveRemediationPath(); got != RemediationDirect {
		t.Fatalf("expected RemediationDirect for zero-value Finding, got %q", got)
	}

	viaController := Finding{RemediationPath: RemediationViaController}
	if got := viaController.EffectiveRemediationPath(); got != RemediationViaController {
		t.Fatalf("expected RemediationViaController to be preserved, got %q", got)
	}
}

func TestExcludeConfig_ShouldExclude_ZeroValue(t *testing.T) {
	var e ExcludeConfig
	if e.ShouldExclude("i-123", map[string]string{"Env": "prod"}) {
		t.Fatal("zero-value ExcludeConfig should not exclude anything")
	}
}

func TestExcludeConfig_ShouldExclude_ResourceID(t *testing.T) {
	e := ExcludeConfig{ResourceIDs: map[string]bool{"i-123": true}}
	if !e.ShouldExclude("i-123", nil) {
		t.Fatal("expected ResourceID match to exclude")
	}
	if e.ShouldExclude("i-999", nil) {
		t.Fatal("expected non-matching ResourceID to not exclude")
	}
}

func TestExcludeConfig_ShouldExclude_TagKeyValue(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"Environment": "production"}}
	if !e.ShouldExclude("i-123", map[string]string{"Environment": "production"}) {
		t.Fatal("expected Key=Value tag match to exclude")
	}
	if e.ShouldExclude("i-123", map[string]string{"Environment": "staging"}) {
		t.Fatal("expected mismatched value to not exclude")
	}
	if e.ShouldExclude("i-123", map[string]string{"Team": "platform"}) {
		t.Fatal("expected missing key to not exclude")
	}
}

func TestExcludeConfig_ShouldExclude_TagKeyOnly(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"awsspectre:ignore": ""}}
	if !e.ShouldExclude("i-123", map[string]string{"awsspectre:ignore": ""}) {
		t.Fatal("expected key-only match with empty value to exclude")
	}
	if !e.ShouldExclude("i-123", map[string]string{"awsspectre:ignore": "true"}) {
		t.Fatal("expected key-only match with any value to exclude")
	}
	if e.ShouldExclude("i-123", map[string]string{"other": "tag"}) {
		t.Fatal("expected missing key to not exclude")
	}
}

func TestExcludeConfig_ShouldExclude_NilTags(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{"Env": "prod"}}
	if e.ShouldExclude("i-123", nil) {
		t.Fatal("nil tags should skip tag matching")
	}
}

func TestExcludeConfig_ShouldExclude_MultipleTags(t *testing.T) {
	e := ExcludeConfig{Tags: map[string]string{
		"Environment": "production",
		"temporary":   "",
	}}
	if !e.ShouldExclude("i-1", map[string]string{"temporary": "yes"}) {
		t.Fatal("expected key-only match on second tag to exclude")
	}
	if e.ShouldExclude("i-1", map[string]string{"Environment": "staging", "Team": "ops"}) {
		t.Fatal("expected no match when no tag matches")
	}
}

func TestEC2TagsToMap(t *testing.T) {
	tags := []ec2types.Tag{
		{Key: awssdk.String("Name"), Value: awssdk.String("web-1")},
		{Key: awssdk.String("Env"), Value: awssdk.String("prod")},
	}
	m := ec2TagsToMap(tags)
	if m["Name"] != "web-1" || m["Env"] != "prod" {
		t.Fatalf("unexpected map: %v", m)
	}
}

func TestEC2TagsToMap_Nil(t *testing.T) {
	if ec2TagsToMap(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestEC2TagsToMap_NilKeyValue(t *testing.T) {
	tags := []ec2types.Tag{
		{Key: nil, Value: awssdk.String("orphan")},
		{Key: awssdk.String("NoValue"), Value: nil},
	}
	m := ec2TagsToMap(tags)
	if len(m) != 1 {
		t.Fatalf("expected 1 entry (nil key skipped), got %d", len(m))
	}
	if m["NoValue"] != "" {
		t.Fatalf("expected empty string for nil value, got %q", m["NoValue"])
	}
}

func TestRDSTagsToMap(t *testing.T) {
	tags := []rdstypes.Tag{
		{Key: awssdk.String("Name"), Value: awssdk.String("db-1")},
		{Key: awssdk.String("Team"), Value: awssdk.String("platform")},
	}
	m := rdsTagsToMap(tags)
	if m["Name"] != "db-1" || m["Team"] != "platform" {
		t.Fatalf("unexpected map: %v", m)
	}
}

func TestRDSTagsToMap_Nil(t *testing.T) {
	if rdsTagsToMap(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}
