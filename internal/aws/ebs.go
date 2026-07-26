package aws

import (
	"context"
	"fmt"
	"time"

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

// Scan examines all EBS volumes in the region for detached volumes and gp2 migration candidates.
func (s *EBSScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	volumes, err := s.listVolumes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list EBS volumes: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(volumes)}
	now := time.Now().UTC()

	for _, vol := range volumes {
		volID := deref(vol.VolumeId)
		if cfg.Exclude.ShouldExclude(volID, ec2TagsToMap(vol.Tags)) {
			continue
		}

		volumeType := string(vol.VolumeType)
		sizeGiB := int(derefInt32(vol.Size))

		if vol.State == ec2types.VolumeStateAvailable {
			// Use CreateTime as a proxy for when it became detached
			// (accurate for volumes that were created detached or detached recently)
			if createTime := vol.CreateTime; createTime != nil {
				daysSinceCreate := int(now.Sub(*createTime).Hours() / 24)
				if daysSinceCreate >= detachedThresholdDays {
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
			}
		}

		// modify-volume only accepts a volume in available or in-use state;
		// creating/deleting/error volumes would reject the remediation command.
		canModify := vol.State == ec2types.VolumeStateAvailable || vol.State == ec2types.VolumeStateInUse
		if vol.VolumeType == ec2types.VolumeTypeGp2 && canModify {
			savings := pricing.MonthlyEBSCost(volumeType, sizeGiB, s.region) - pricing.MonthlyEBSCost(string(ec2types.VolumeTypeGp3), sizeGiB, s.region)
			if savings < 0 {
				savings = 0
			}
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingGP2MigrationCandidate,
				Severity:              SeverityLow,
				ResourceType:          ResourceEBS,
				ResourceID:            volID,
				ResourceName:          volumeName(vol),
				Region:                s.region,
				Message:               fmt.Sprintf("gp2 volume %d GiB — migrate to gp3 for equivalent baseline performance at lower cost", sizeGiB),
				EstimatedMonthlyWaste: savings,
				// Always visible regardless of --min-monthly-cost: per-volume savings
				// are often below the default threshold, but the win is zero-risk and
				// compounds across a fleet (WO-194 hygiene pattern; WO-221 precedent).
				Hygiene: true,
				Metadata: map[string]any{
					"volume_type": volumeType,
					"size_gib":    sizeGiB,
					"remediation": fmt.Sprintf("aws ec2 modify-volume --volume-id %s --volume-type gp3", volID),
				},
			})
		}
	}

	return result, nil
}

func (s *EBSScanner) listVolumes(ctx context.Context) ([]ec2types.Volume, error) {
	var volumes []ec2types.Volume
	paginator := ec2.NewDescribeVolumesPaginator(s.client, &ec2.DescribeVolumesInput{})

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
	return tagValue(vol.Tags, "Name")
}

func derefInt32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
