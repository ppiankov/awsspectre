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

// detachedThresholdDays is the minimum days a volume must be detached to be flagged.
const detachedThresholdDays = 7

// EBSAPI is the minimal interface for EBS volume operations.
type EBSAPI interface {
	DescribeVolumes(ctx context.Context, input *ec2.DescribeVolumesInput, opts ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// EBSScanner detects detached EBS volumes.
type EBSScanner struct {
	client EBSAPI
	region string
}

// NewEBSScanner creates a scanner for EBS volumes.
func NewEBSScanner(client EBSAPI, region string) *EBSScanner {
	return &EBSScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *EBSScanner) Type() ResourceType {
	return ResourceEBS
}

// Scan examines all EBS volumes in the region for detached volumes.
func (s *EBSScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	volumes, err := s.listAvailableVolumes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list EBS volumes: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(volumes)}
	now := time.Now().UTC()

	for _, vol := range volumes {
		volID := deref(vol.VolumeId)
		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[volID] {
			continue
		}

		// Volume is in "available" state (not attached)
		// Use CreateTime as a proxy for when it became detached
		// (accurate for volumes that were created detached or detached recently)
		createTime := vol.CreateTime
		if createTime == nil {
			continue
		}

		daysSinceCreate := int(now.Sub(*createTime).Hours() / 24)
		if daysSinceCreate < detachedThresholdDays {
			continue
		}

		volumeType := string(vol.VolumeType)
		sizeGiB := int(derefInt32(vol.Size))
		cost := pricing.MonthlyEBSCost(volumeType, sizeGiB, s.region)

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingDetachedEBS,
			Severity:              SeverityHigh,
			ResourceType:          ResourceEBS,
			ResourceID:            volID,
			ResourceName:          volumeName(vol),
			Region:                s.region,
			Message:               fmt.Sprintf("Detached %d days, %s %d GiB", daysSinceCreate, volumeType, sizeGiB),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"volume_type":       volumeType,
				"size_gib":          sizeGiB,
				"days_detached":     daysSinceCreate,
				"availability_zone": deref(vol.AvailabilityZone),
			},
		})
	}

	return result, nil
}

func (s *EBSScanner) listAvailableVolumes(ctx context.Context) ([]ec2types.Volume, error) {
	var volumes []ec2types.Volume
	paginator := ec2.NewDescribeVolumesPaginator(s.client, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("status"),
				Values: []string{"available"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, page.Volumes...)
	}
	return volumes, nil
}

func volumeName(vol ec2types.Volume) string {
	for _, tag := range vol.Tags {
		if deref(tag.Key) == "Name" {
			return deref(tag.Value)
		}
	}
	return ""
}

func derefInt32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
