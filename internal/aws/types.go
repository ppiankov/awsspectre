package aws

import (
	"encoding/json"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// Severity levels for findings.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// RemediationPath classifies how a finding should be acted on — WO-228.
// A structured, machine-readable alternative to string-matching a finding's
// Message to tell "safe to delete directly" apart from "needs indirect
// action" or "needs manual review before acting."
type RemediationPath string

const (
	// RemediationDirect: the resource itself is the fix target. The safe
	// default for scanners with no ownership-awareness logic.
	RemediationDirect RemediationPath = "direct"
	// RemediationViaController: fix by acting on the owning Kubernetes/ECS/
	// IaC-managed resource, not this one directly (e.g. a load balancer
	// managed by a Kubernetes Service/Ingress controller — WO-220).
	RemediationViaController RemediationPath = "via_controller"
	// RemediationNeedsReview: the finding's confidence is lower than usual
	// and warrants manual review before acting.
	RemediationNeedsReview RemediationPath = "needs_review"
)

// ResourceType identifies the AWS resource being audited.
type ResourceType string

const (
	ResourceEC2           ResourceType = "ec2"
	ResourceEBS           ResourceType = "ebs"
	ResourceEIP           ResourceType = "eip"
	ResourceALB           ResourceType = "alb"
	ResourceNLB           ResourceType = "nlb"
	ResourceNATGateway    ResourceType = "nat_gateway"
	ResourceRDS           ResourceType = "rds"
	ResourceSnapshot      ResourceType = "snapshot"
	ResourceSecurityGroup ResourceType = "security_group"
	ResourceLambda        ResourceType = "lambda"
	ResourceKinesis       ResourceType = "kinesis"
	ResourceFirehose      ResourceType = "firehose"
	ResourceSQS           ResourceType = "sqs"
	ResourceSNS           ResourceType = "sns"
	ResourceCloudFront    ResourceType = "cloudfront"     // WO-189: global CloudFront hygiene scanner.
	ResourceLogGroup      ResourceType = "log_group"      // WO-221: CloudWatch Logs retention scanner.
	ResourceECR           ResourceType = "ecr_repository" // WO-225: ECR repository storage/untagged-image scanner.
)

// FindingID identifies the type of waste detected.
type FindingID string

const (
	FindingIdleEC2                FindingID = "IDLE_EC2"
	FindingStoppedEC2             FindingID = "STOPPED_EC2"
	FindingDetachedEBS            FindingID = "DETACHED_EBS"
	FindingUnusedEIP              FindingID = "UNUSED_EIP"
	FindingIdleALB                FindingID = "IDLE_ALB"
	FindingIdleNLB                FindingID = "IDLE_NLB"
	FindingIdleNATGateway         FindingID = "IDLE_NAT_GATEWAY"
	FindingLowTrafficNATGateway   FindingID = "LOW_TRAFFIC_NAT_GATEWAY"
	FindingIdleRDS                FindingID = "IDLE_RDS"
	FindingStaleSnapshot          FindingID = "STALE_SNAPSHOT"
	FindingUnusedSecurityGroup    FindingID = "UNUSED_SECURITY_GROUP"
	FindingIdleLambda             FindingID = "IDLE_LAMBDA"
	FindingKinesisStreamIdle      FindingID = "KINESIS_STREAM_IDLE"
	FindingKinesisOverProvisioned FindingID = "KINESIS_OVER_PROVISIONED"
	FindingKinesisFirehoseIdle    FindingID = "KINESIS_FIREHOSE_IDLE"
	FindingSQSIdle                FindingID = "SQS_IDLE"
	FindingSQSDLQOrphaned         FindingID = "SQS_DLQ_ORPHANED"
	FindingSQSNoConsumer          FindingID = "SQS_NO_CONSUMER"
	FindingSNSNoSubscribers       FindingID = "SNS_NO_SUBSCRIBERS"
	FindingSNSIdle                FindingID = "SNS_IDLE"
	FindingCloudFrontDisabled     FindingID = "CLOUDFRONT_DISABLED"       // WO-189: disabled distribution hygiene signal.
	FindingCloudFrontIdle         FindingID = "CLOUDFRONT_IDLE"           // WO-189: zero-request distribution hygiene signal.
	FindingLogGroupNoRetention    FindingID = "LOG_GROUP_NO_RETENTION"    // WO-221: unbounded log-retention risk.
	FindingGP2MigrationCandidate  FindingID = "GP2_MIGRATION_CANDIDATE"   // WO-222: gp2 volume with a same-behavior gp3 cost win.
	FindingECRNoLifecyclePolicy   FindingID = "ECR_NO_LIFECYCLE_POLICY"   // WO-225: unbounded image retention risk.
	FindingECRUntaggedImageSprawl FindingID = "ECR_UNTAGGED_IMAGE_SPRAWL" // WO-225: untagged images accumulating storage cost.
)

// Finding represents a single waste detection result.
type Finding struct {
	ID                    FindingID       `json:"id"`
	Severity              Severity        `json:"severity"`
	ResourceType          ResourceType    `json:"resource_type"`
	ResourceID            string          `json:"resource_id"`
	ResourceName          string          `json:"resource_name,omitempty"`
	Region                string          `json:"region"`
	Message               string          `json:"message"`
	EstimatedMonthlyWaste float64         `json:"estimated_monthly_waste"`
	Hygiene               bool            `json:"hygiene,omitempty"` // WO-194: zero-waste hygiene findings bypass cost filtering structurally.
	RemediationPath       RemediationPath `json:"remediation_path,omitempty"`
	Metadata              map[string]any  `json:"metadata,omitempty"`
}

// EffectiveRemediationPath returns f.RemediationPath, defaulting to
// RemediationDirect when unset — the safe default for scanners with no
// ownership-awareness logic. Used by JSON serialization and any other
// consumer that needs the resolved value rather than the raw zero value.
func (f Finding) EffectiveRemediationPath() RemediationPath {
	if f.RemediationPath == "" {
		return RemediationDirect
	}
	return f.RemediationPath
}

// MarshalJSON serializes Finding with RemediationPath resolved to its
// effective value (defaulting to "direct") — WO-228. Scanners with no
// ownership-awareness logic don't need to set this field explicitly; the
// output always carries an explicit, machine-readable value rather than an
// empty string.
func (f Finding) MarshalJSON() ([]byte, error) {
	type alias Finding
	return json.Marshal(struct {
		alias
		RemediationPath RemediationPath `json:"remediation_path"`
	}{
		alias:           alias(f),
		RemediationPath: f.EffectiveRemediationPath(),
	})
}

// ScanResult holds all findings from scanning a set of resources.
type ScanResult struct {
	Findings         []Finding `json:"findings"`
	Errors           []string  `json:"errors,omitempty"`
	ResourcesScanned int       `json:"resources_scanned"`
	RegionsScanned   int       `json:"regions_scanned"`
}

// ScanConfig holds parameters that control scanning behavior.
type ScanConfig struct {
	IdleDays             int
	StaleDays            int
	MinMonthlyCost       float64
	IdleCPUThreshold     float64
	HighMemoryThreshold  float64
	StoppedThresholdDays int
	NATGWLowTrafficGB    float64
	ECRUntaggedThreshold int
	Exclude              ExcludeConfig
}

// ExcludeConfig holds resource exclusion rules.
type ExcludeConfig struct {
	ResourceIDs map[string]bool
	Tags        map[string]string
}

// ShouldExclude returns true if a resource should be skipped based on its ID or tags.
// A nil tags map skips tag matching (used when tags are unavailable).
func (e ExcludeConfig) ShouldExclude(resourceID string, tags map[string]string) bool {
	if e.ResourceIDs[resourceID] {
		return true
	}
	if tags == nil || len(e.Tags) == 0 {
		return false
	}
	for k, v := range e.Tags {
		tagVal, exists := tags[k]
		if !exists {
			continue
		}
		if v == "" || tagVal == v {
			return true
		}
	}
	return false
}

// tagValue returns the value of the first tag matching key, or "" if absent.
func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if deref(t.Key) == key {
			return deref(t.Value)
		}
	}
	return ""
}

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil {
			v := ""
			if t.Value != nil {
				v = *t.Value
			}
			m[*t.Key] = v
		}
	}
	return m
}

func rdsTagsToMap(tags []rdstypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil {
			v := ""
			if t.Value != nil {
				v = *t.Value
			}
			m[*t.Key] = v
		}
	}
	return m
}

// ScanProgress reports scanning progress to callers.
type ScanProgress struct {
	Region    string
	Scanner   string
	Message   string
	Timestamp time.Time
}
