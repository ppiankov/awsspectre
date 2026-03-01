package aws

import (
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
)

// Finding represents a single waste detection result.
type Finding struct {
	ID                    FindingID      `json:"id"`
	Severity              Severity       `json:"severity"`
	ResourceType          ResourceType   `json:"resource_type"`
	ResourceID            string         `json:"resource_id"`
	ResourceName          string         `json:"resource_name,omitempty"`
	Region                string         `json:"region"`
	Message               string         `json:"message"`
	EstimatedMonthlyWaste float64        `json:"estimated_monthly_waste"`
	Metadata              map[string]any `json:"metadata,omitempty"`
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
