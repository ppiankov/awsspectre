package aws

import "time"

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
)

// FindingID identifies the type of waste detected.
type FindingID string

const (
	FindingIdleEC2             FindingID = "IDLE_EC2"
	FindingStoppedEC2          FindingID = "STOPPED_EC2"
	FindingDetachedEBS         FindingID = "DETACHED_EBS"
	FindingUnusedEIP           FindingID = "UNUSED_EIP"
	FindingIdleALB             FindingID = "IDLE_ALB"
	FindingIdleNLB             FindingID = "IDLE_NLB"
	FindingIdleNATGateway      FindingID = "IDLE_NAT_GATEWAY"
	FindingIdleRDS             FindingID = "IDLE_RDS"
	FindingStaleSnapshot       FindingID = "STALE_SNAPSHOT"
	FindingUnusedSecurityGroup FindingID = "UNUSED_SECURITY_GROUP"
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
	Exclude              ExcludeConfig
}

// ExcludeConfig holds resource exclusion rules.
type ExcludeConfig struct {
	ResourceIDs map[string]bool
	Tags        map[string]string
}

// ScanProgress reports scanning progress to callers.
type ScanProgress struct {
	Region    string
	Scanner   string
	Message   string
	Timestamp time.Time
}
