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

func TestSampleIAMPolicyIncludesWO218TagFetchPermissions(t *testing.T) {
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

	// WO-218 (v0.6.0) added these tag-fetch calls so --exclude-tags would work
	// for ELB, Kinesis, Firehose, Lambda, SNS, SQS, and CloudFront, but the
	// generated policy was never updated to match — WO-230.
	required := []string{
		"elasticloadbalancing:DescribeTags",
		"kinesis:ListTagsForStream",
		"firehose:ListTagsForDeliveryStream",
		"lambda:ListTags",
		"sns:ListTagsForResource",
		"sqs:ListQueueTags",
		"cloudfront:ListTagsForResource",
	}
	for _, action := range required {
		if !actions[action] {
			t.Errorf("expected sample IAM policy to include %s", action)
		}
	}
}

func TestSampleIAMPolicyIncludesFirehoseDescribeDeliveryStream(t *testing.T) {
	var policy samplePolicyDocument
	if err := json.Unmarshal([]byte(sampleIAMPolicy), &policy); err != nil {
		t.Fatalf("unmarshal sample IAM policy: %v", err)
	}

	actions := make(map[string]bool, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		actions[action] = true
	}

	// WO-244: the Firehose scanner calls DescribeDeliveryStream to determine
	// a delivery stream's source type, learning from the WO-218/WO-230
	// lesson that new API calls must be reflected in the generated policy
	// immediately, not backfilled later.
	if !actions["firehose:DescribeDeliveryStream"] {
		t.Fatal("expected sample IAM policy to include firehose:DescribeDeliveryStream")
	}
}

func TestSampleIAMPolicyIncludesASGReferencedSecurityGroupPermissions(t *testing.T) {
	var policy samplePolicyDocument
	if err := json.Unmarshal([]byte(sampleIAMPolicy), &policy); err != nil {
		t.Fatalf("unmarshal sample IAM policy: %v", err)
	}

	actions := make(map[string]bool, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		actions[action] = true
	}

	// WO-232: the security group scanner calls these to detect a security
	// group referenced by an Auto Scaling Group's launch template/launch
	// configuration, regardless of the ASG's current desired capacity.
	required := []string{
		"ec2:DescribeLaunchTemplateVersions",
		"autoscaling:DescribeAutoScalingGroups",
		"autoscaling:DescribeLaunchConfigurations",
	}
	for _, action := range required {
		if !actions[action] {
			t.Errorf("expected sample IAM policy to include %s", action)
		}
	}
}

func TestSampleIAMPolicyIncludesECRScanPermissions(t *testing.T) {
	var policy samplePolicyDocument
	if err := json.Unmarshal([]byte(sampleIAMPolicy), &policy); err != nil {
		t.Fatalf("unmarshal sample IAM policy: %v", err)
	}

	actions := make(map[string]bool, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		actions[action] = true
	}

	// WO-225: the ECR scanner calls these to list repositories, check for a
	// configured lifecycle policy, and count untagged images.
	required := []string{
		"ecr:DescribeRepositories",
		"ecr:GetLifecyclePolicy",
		"ecr:DescribeImages",
	}
	for _, action := range required {
		if !actions[action] {
			t.Errorf("expected sample IAM policy to include %s", action)
		}
	}
}

func TestSampleIAMPolicyIncludesLambdaEventSourcePermissions(t *testing.T) {
	var policy samplePolicyDocument
	if err := json.Unmarshal([]byte(sampleIAMPolicy), &policy); err != nil {
		t.Fatalf("unmarshal sample IAM policy: %v", err)
	}

	actions := make(map[string]bool, len(policy.Statement[0].Action))
	for _, action := range policy.Statement[0].Action {
		actions[action] = true
	}

	// WO-246: the Lambda scanner calls ListEventSourceMappings to check
	// whether a function with zero invocations has a live event source
	// (SQS/DynamoDB/Kinesis) — a rare-but-wired trigger, not orphaned.
	required := []string{
		"lambda:ListEventSourceMappings",
	}
	for _, action := range required {
		if !actions[action] {
			t.Errorf("expected sample IAM policy to include %s", action)
		}
	}
}
