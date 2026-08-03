package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initFlags struct {
	force bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config and IAM policy",
	Long:  `Creates a sample .awsspectre.yaml config file and an IAM policy JSON file for read-only access.`,
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing files")
}

func runInit(_ *cobra.Command, _ []string) error {
	configPath := ".awsspectre.yaml"
	policyPath := "awsspectre-policy.json"

	wrote := 0

	if err := writeIfNotExists(configPath, sampleConfig, initFlags.force); err != nil {
		return err
	}
	wrote++

	if err := writeIfNotExists(policyPath, sampleIAMPolicy, initFlags.force); err != nil {
		return err
	}
	wrote++

	if wrote > 0 {
		fmt.Printf("Created %s and %s\n", configPath, policyPath)
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Edit .awsspectre.yaml to customize scan settings")
		fmt.Println("  2. Apply awsspectre-policy.json to your AWS IAM role/user")
		fmt.Println("  3. Run: awsspectre scan")
	}
	return nil
}

func writeIfNotExists(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Skipping %s (already exists, use --force to overwrite)\n", path)
			return nil
		}
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

const sampleConfig = `# awsspectre configuration
# See: https://github.com/ppiankov/awsspectre

# AWS profile (or set AWS_PROFILE env var)
# profile: default

# Regions to scan (default: all enabled regions)
# regions:
#   - us-east-1
#   - us-west-2
#   - eu-west-1

# Lookback window for utilization metrics (days)
idle_days: 7

# Age threshold for stale snapshots/volumes (days)
stale_days: 90

# Minimum monthly cost to report ($)
min_monthly_cost: 1.0

# Output format: text or json
format: text

# Scan timeout
timeout: 10m

# Idle detection thresholds
# idle_cpu_threshold: 5.0
# high_memory_threshold: 50.0
# idle_cpu_burst_threshold: 30.0
# idle_ec2_network_gb: 1.0
# stopped_threshold_days: 30
# nat_gw_low_traffic_gb: 1.0
# ecr_untagged_threshold: 20

# Resources to exclude from scanning
# exclude:
#   resource_ids:
#     - i-0abc123
#   tags:
#     - "Environment=production"
#     - "awsspectre:ignore"
`

// WO-199: generated IAM policy must cover CloudFront distribution inventory.
// WO-221: also covers CloudWatch Logs retention/tag inventory.
// WO-232: also covers Auto Scaling Group / launch template inspection for
// ASG-referenced security group detection.
// WO-225: also covers ECR repository/image inventory.
// WO-223: also covers ENI availability/inventory.
const sampleIAMPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AwsSpectreReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses",
        "ec2:DescribeNatGateways",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "ec2:DescribeRegions",
        "ec2:DescribeLaunchTemplateVersions",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeTags",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "lambda:ListEventSourceMappings",
        "kinesis:ListStreams",
        "kinesis:DescribeStreamSummary",
        "kinesis:ListTagsForStream",
        "firehose:ListDeliveryStreams",
        "firehose:ListTagsForDeliveryStream",
        "firehose:DescribeDeliveryStream",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sqs:ListQueueTags",
        "sns:ListTopics",
        "sns:ListSubscriptionsByTopic",
        "sns:ListTagsForResource",
        "cloudfront:ListDistributions",
        "cloudfront:ListTagsForResource",
        "cloudwatch:GetMetricData",
        "logs:DescribeLogGroups",
        "logs:ListTagsForResource",
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "ecr:DescribeImages",
        "cloudtrail:LookupEvents",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
`
