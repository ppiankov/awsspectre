package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// SnapshotAPI is the minimal interface for snapshot and AMI operations.
type SnapshotAPI interface {
	DescribeSnapshots(ctx context.Context, input *ec2.DescribeSnapshotsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeImages(ctx context.Context, input *ec2.DescribeImagesInput, opts ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// SnapshotScanner detects stale snapshots with no AMI reference.
type SnapshotScanner struct {
	client SNAPSHOTAPI
	region string
}

// SNAPSHOTAPI is an alias used internally; exported interface is SnapshotAPI.
type SNAPSHOTAPI = SnapshotAPI

// NewSnapshotScanner creates a scanner for EBS snapshots.
func NewSnapshotScanner(client SnapshotAPI, region string) *SnapshotScanner {
	return &SnapshotScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *SnapshotScanner) Type() ResourceType {
	return ResourceSnapshot
}

// Scan examines all self-owned snapshots for stale entries.
func (s *SnapshotScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	snapshots, err := s.listOwnedSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(snapshots)}
	if len(snapshots) == 0 {
		return result, nil
	}

	// Build a set of snapshot IDs referenced by AMIs
	amiSnaps, err := s.amiReferencedSnapshots(ctx)
	if err != nil {
		// Non-fatal: proceed without AMI filtering
		amiSnaps = make(map[string]bool)
	}

	now := time.Now().UTC()
	for _, snap := range snapshots {
		snapID := deref(snap.SnapshotId)
		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[snapID] {
			continue
		}

		if snap.StartTime == nil {
			continue
		}

		ageDays := int(now.Sub(*snap.StartTime).Hours() / 24)
		if ageDays < cfg.StaleDays {
			continue
		}

		// Skip snapshots referenced by an AMI
		if amiSnaps[snapID] {
			continue
		}

		sizeGiB := int(derefInt32(snap.VolumeSize))
		cost := pricing.MonthlySnapshotCost(sizeGiB, s.region)

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingStaleSnapshot,
			Severity:              SeverityMedium,
			ResourceType:          ResourceSnapshot,
			ResourceID:            snapID,
			ResourceName:          snapshotName(snap),
			Region:                s.region,
			Message:               fmt.Sprintf("Snapshot %d days old, %d GiB, no AMI reference", ageDays, sizeGiB),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"age_days":  ageDays,
				"size_gib":  sizeGiB,
				"volume_id": deref(snap.VolumeId),
			},
		})
	}

	return result, nil
}

func (s *SnapshotScanner) listOwnedSnapshots(ctx context.Context) ([]ec2types.Snapshot, error) {
	var snapshots []ec2types.Snapshot
	paginator := ec2.NewDescribeSnapshotsPaginator(s.client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, page.Snapshots...)
	}
	return snapshots, nil
}

func (s *SnapshotScanner) amiReferencedSnapshots(ctx context.Context) (map[string]bool, error) {
	out, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
		Filters: []ec2types.Filter{
			{Name: awssdk.String("state"), Values: []string{"available"}},
		},
	})
	if err != nil {
		return nil, err
	}

	refs := make(map[string]bool)
	for _, img := range out.Images {
		for _, mapping := range img.BlockDeviceMappings {
			if mapping.Ebs != nil && mapping.Ebs.SnapshotId != nil {
				refs[*mapping.Ebs.SnapshotId] = true
			}
		}
	}
	return refs, nil
}

func snapshotName(snap ec2types.Snapshot) string {
	for _, tag := range snap.Tags {
		if deref(tag.Key) == "Name" {
			return deref(tag.Value)
		}
	}
	return deref(snap.Description)
}
