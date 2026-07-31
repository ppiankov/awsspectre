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

// csiEBSVolumeTagKeys are tags the AWS EBS CSI driver (or the older in-tree
// AWS provisioner) sets on a volume it dynamically provisioned for a
// Kubernetes PersistentVolume. Each is exclusively set by that provisioning
// path — unlike WO-220's eks:eks-cluster-name tag, none of these are shared
// with an unrelated purpose, so any one alone is a safe, sufficient signal
// (no pairing required) — WO-231.
const (
	csiPVCNameTagKey      = "kubernetes.io/created-for/pvc/name"
	csiPVCNamespaceTagKey = "kubernetes.io/created-for/pvc/namespace"
	csiPVNameTagKey       = "kubernetes.io/created-for/pv/name"
	csiClusterTagKey      = "ebs.csi.aws.com/cluster"
)

// isCSIManagedEBSVolume reports whether tags mark this volume as provisioned
// by the AWS EBS CSI driver for a Kubernetes PersistentVolume, plus the PVC
// name/namespace when present for triage guidance.
func isCSIManagedEBSVolume(tags map[string]string) (managed bool, pvcName, pvcNamespace string) {
	pvcName = tags[csiPVCNameTagKey]
	pvcNamespace = tags[csiPVCNamespaceTagKey]
	_, hasCluster := tags[csiClusterTagKey]
	_, hasPVName := tags[csiPVNameTagKey]
	managed = hasCluster || hasPVName || pvcName != "" || pvcNamespace != ""
	return managed, pvcName, pvcNamespace
}

// EBSAPI is the minimal interface for EBS volume operations.
type EBSAPI interface {
	DescribeVolumes(ctx context.Context, input *ec2.DescribeVolumesInput, opts ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// EBSScanner detects detached EBS volumes.
type EBSScanner struct {
	client     EBSAPI
	region     string
	cloudTrail CloudTrailAPI
}

// NewEBSScanner creates a scanner for EBS volumes.
func NewEBSScanner(client EBSAPI, region string) *EBSScanner {
	return &EBSScanner{client: client, region: region}
}

// SetCloudTrailClient enables CloudTrail-backed detach-time lookup (WO-242).
// Optional: without it, DETACHED_EBS falls back to its CreateTime-based estimate.
func (s *EBSScanner) SetCloudTrailClient(client CloudTrailAPI) {
	s.cloudTrail = client
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
		tags := ec2TagsToMap(vol.Tags)
		if cfg.Exclude.ShouldExclude(volID, tags) {
			continue
		}

		volumeType := string(vol.VolumeType)
		sizeGiB := int(derefInt32(vol.Size))

		if vol.State == ec2types.VolumeStateAvailable {
			// CreateTime is the fallback proxy for when the volume became
			// detached (accurate for volumes created detached or detached
			// recently); prefer the real CloudTrail DetachVolume event when
			// available, since a long-lived volume that recently detached
			// after months attached would otherwise be wildly overcounted
			// — WO-242.
			if createTime := vol.CreateTime; createTime != nil {
				// The real detach time can only be >= CreateTime, so the
				// CloudTrail-corrected day count can only be <= this naive
				// estimate — only look it up when the naive estimate already
				// clears the threshold, since a lookup can never turn a
				// below-threshold volume into an above-threshold one.
				daysDetached := int(now.Sub(*createTime).Hours() / 24)
				if daysDetached >= detachedThresholdDays {
					if detachTime, ok := lookupMostRecentEventTime(ctx, s.cloudTrail, volID, "DetachVolume"); ok {
						daysDetached = int(now.Sub(detachTime).Hours() / 24)
					}
				}
				if daysDetached >= detachedThresholdDays {
					cost := pricing.MonthlyEBSCost(volumeType, sizeGiB, s.region)
					msg := fmt.Sprintf("Detached %d days, %s %d GiB", daysDetached, volumeType, sizeGiB)
					remediationPath := RemediationDirect
					meta := map[string]any{
						"volume_type":       volumeType,
						"size_gib":          sizeGiB,
						"days_detached":     daysDetached,
						"availability_zone": deref(vol.AvailabilityZone),
					}

					if csiManaged, pvcName, pvcNamespace := isCSIManagedEBSVolume(tags); csiManaged {
						// WO-231: same defect class as WO-220 for load balancers.
						// A CSI-managed volume can still be genuine waste (e.g. a
						// deleted PVC with a Retain reclaim policy), so the finding
						// stays visible — but blind "detach and delete" advice is
						// wrong without first checking whether a PersistentVolume
						// still claims it.
						remediationPath = RemediationNeedsReview
						meta["csi_managed"] = true
						if pvcName != "" && pvcNamespace != "" {
							meta["pvc_name"] = pvcName
							meta["pvc_namespace"] = pvcNamespace
							msg += fmt.Sprintf(" — provisioned by a Kubernetes PersistentVolume for PVC %q in namespace %q; verify with `kubectl get pv` before deleting directly", pvcName, pvcNamespace)
						} else {
							msg += " — provisioned by a Kubernetes PersistentVolume; verify with `kubectl get pv` before deleting directly"
						}
					}

					result.Findings = append(result.Findings, Finding{
						ID:                    FindingDetachedEBS,
						Severity:              SeverityHigh,
						ResourceType:          ResourceEBS,
						ResourceID:            volID,
						ResourceName:          volumeName(vol),
						Region:                s.region,
						Message:               msg,
						EstimatedMonthlyWaste: cost,
						RemediationPath:       remediationPath,
						Metadata:              meta,
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
