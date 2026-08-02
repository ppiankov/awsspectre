package aws

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// defaultIdleCPUBurstThreshold is the daily-max CPU % that counts as a spike
// day for WO-247 burst detection when ScanConfig.IdleCPUBurstThreshold is unset
// (zero) — the defensive fallback for direct ScanConfig construction; the CLI
// flag itself defaults to the same value. Well above the 5% idle floor so a
// spike day reflects real work, not noise.
const defaultIdleCPUBurstThreshold = 30.0

// minBurstDays is the minimum number of distinct spike days within the
// lookback window required to call a low-average instance "periodic/burst"
// rather than flatly idle (WO-247). Two+ separate days rules out a one-off
// (deploy, boot, patch) and is the smallest count that means "recurring."
// Chosen as a const rather than a flag: it is a definitional threshold for
// "recurring," not an ops-tunable.
const minBurstDays = 2

// detectCPUBurst reports whether dailyMaxima show a recurring spike pattern:
// at least minBurstDays daily maxima at or above burstThreshold. Returns the
// spike-day count, the peak daily max observed, and whether the burst pattern
// holds. An empty/short series (e.g. a brand-new instance with <1 day of data)
// cannot be "recurring" and reports no burst.
//
// detectCPUBurstCalls is a test-observability counter (tests reset it per
// case) so a test can assert burst detection was never reached for an instance
// skipped by an earlier override (GPU/memory) — pinning the
// override-before-burst ordering. Not consulted by production logic. It is an
// atomic because production's MultiRegionScanner runs regions concurrently
// (each with its own EC2Scanner but sharing this package-global), so a plain
// int would be a data race under -race even though the value is unused in
// production — WO-256.
var detectCPUBurstCalls atomic.Int64

func detectCPUBurst(dailyMaxima []float64, burstThreshold float64) (spikeDays int, peakMax float64, ok bool) {
	detectCPUBurstCalls.Add(1)
	for _, m := range dailyMaxima {
		if m > peakMax {
			peakMax = m
		}
		if m >= burstThreshold {
			spikeDays++
		}
	}
	return spikeDays, peakMax, spikeDays >= minBurstDays
}

// eksNodeGroupTagKeys are tags set by EKS-managed node groups and the
// cluster-autoscaler/Karpenter on the EC2 instances they own. Any one of
// these alone is a sufficient signal — the instance is scaled up/down by its
// owning node group or Auto Scaling Group, not removed by terminating it
// directly — WO-239 (mirrors WO-220's ELB precedent).
var eksNodeGroupTagKeys = []string{
	"aws:autoscaling:groupName",
	"eks:cluster-name",
	"aws:eks:cluster-name",
}

// kubernetesClusterTagPrefix is the key prefix for the
// "kubernetes.io/cluster/<name>=owned" convention used by both the legacy
// in-tree cloud provider and cluster-autoscaler/Karpenter to mark nodes as
// owned by a specific cluster — WO-239.
const kubernetesClusterTagPrefix = "kubernetes.io/cluster/"

func isNodeGroupManagedEC2(tags map[string]string) (managed bool) {
	for _, key := range eksNodeGroupTagKeys {
		if _, ok := tags[key]; ok {
			return true
		}
	}
	for key, value := range tags {
		if strings.HasPrefix(key, kubernetesClusterTagPrefix) && value == "owned" {
			return true
		}
	}
	return false
}

// EC2API is the minimal interface for EC2 instance operations.
type EC2API interface {
	DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVolumes(ctx context.Context, input *ec2.DescribeVolumesInput, opts ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// EC2Scanner detects idle and stopped EC2 instances.
type EC2Scanner struct {
	client     EC2API
	metrics    *MetricsFetcher
	region     string
	cloudTrail CloudTrailAPI
}

// NewEC2Scanner creates a scanner for EC2 instances.
func NewEC2Scanner(client EC2API, metrics *MetricsFetcher, region string) *EC2Scanner {
	return &EC2Scanner{client: client, metrics: metrics, region: region}
}

// SetCloudTrailClient enables CloudTrail-backed stop-time lookup (WO-243).
// Optional: without it, STOPPED_EC2 falls back to its LaunchTime-based estimate.
func (s *EC2Scanner) SetCloudTrailClient(client CloudTrailAPI) {
	s.cloudTrail = client
}

// Type returns the resource type this scanner handles.
func (s *EC2Scanner) Type() ResourceType {
	return ResourceEC2
}

// Scan examines all EC2 instances in the region for waste.
func (s *EC2Scanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	instances, err := s.listInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("list EC2 instances: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(instances)}
	if len(instances) == 0 {
		return result, nil
	}

	// Check stopped instances
	now := time.Now().UTC()
	var runningIDs []string
	stoppedVolumeIDs := map[string][]string{} // instanceID → []volumeID
	for _, inst := range instances {
		if cfg.Exclude.ShouldExclude(deref(inst.InstanceId), ec2TagsToMap(inst.Tags)) {
			continue
		}

		if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameStopped {
			instID := deref(inst.InstanceId)
			// LaunchTime is the fallback proxy for when the instance was
			// stopped; prefer the real CloudTrail StopInstances event when
			// available, since LaunchTime alone can overcount by however
			// long the instance ran before it was ever stopped — WO-243.
			stoppedAt := stoppedSince(inst)
			if stoppedAt.IsZero() {
				continue
			}
			daysStopped := int(now.Sub(stoppedAt).Hours() / 24)
			// The real stop time can only be >= LaunchTime, so the
			// CloudTrail-corrected day count can only be <= this naive
			// estimate — only look it up when the naive estimate already
			// clears the threshold, since a lookup can never turn a
			// below-threshold instance into an above-threshold one.
			if daysStopped >= cfg.StoppedThresholdDays {
				if stopTime, ok := lookupMostRecentEventTime(ctx, s.cloudTrail, instID, "StopInstances"); ok {
					daysStopped = int(now.Sub(stopTime).Hours() / 24)
				}
			}
			if daysStopped >= cfg.StoppedThresholdDays {
				instanceType := string(inst.InstanceType)

				// Collect attached volume IDs for EBS cost lookup
				var volIDs []string
				for _, bdm := range inst.BlockDeviceMappings {
					if bdm.Ebs != nil && bdm.Ebs.VolumeId != nil {
						volIDs = append(volIDs, *bdm.Ebs.VolumeId)
					}
				}
				stoppedVolumeIDs[instID] = volIDs

				result.Findings = append(result.Findings, Finding{
					ID:                    FindingStoppedEC2,
					Severity:              SeverityMedium,
					ResourceType:          ResourceEC2,
					ResourceID:            instID,
					ResourceName:          instanceName(inst),
					Region:                s.region,
					Message:               fmt.Sprintf("Stopped for %d days", daysStopped),
					EstimatedMonthlyWaste: 0,
					Metadata: map[string]any{
						"instance_type": instanceType,
						"days_stopped":  daysStopped,
						"state":         "stopped",
					},
				})
			}
			continue
		}

		if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameRunning {
			runningIDs = append(runningIDs, deref(inst.InstanceId))
		}
	}

	// Enrich stopped findings with EBS volume costs
	s.enrichStoppedWithEBSCost(ctx, result, stoppedVolumeIDs)

	// Check CPU and memory utilization for running instances
	if len(runningIDs) > 0 {
		cpuMap, err := s.metrics.FetchAverage(ctx, "AWS/EC2", "CPUUtilization", "InstanceId", runningIDs, cfg.IdleDays)
		if err != nil {
			slog.Warn("Failed to fetch EC2 CPU metrics", "region", s.region, "error", err)
		} else {
			// Fetch memory utilization from CloudWatch Agent (optional — not all instances have the agent)
			memMap, memErr := s.metrics.FetchAverage(ctx, "CWAgent", "mem_used_percent", "InstanceId", runningIDs, cfg.IdleDays)
			if memErr != nil {
				slog.Warn("Failed to fetch EC2 memory metrics", "region", s.region, "error", memErr)
				memMap = make(map[string]float64)
			}

			// Fetch GPU utilization for GPU-family instances (optional — requires the
			// CloudWatch agent's NVIDIA GPU metrics plugin) — WO-235: a GPU-bound
			// workload commonly runs with low host CPU while the GPU itself is
			// saturated, since the CPU's job is mostly feeding the accelerator.
			// Note: Inferentia (inf1/inf2) and Trainium (trn1) report utilization via
			// separate Neuron metrics, not this NVIDIA-agent metric, so the override
			// is currently inert for those families — they fall back to CPU-only,
			// same as an instance with no GPU-metrics agent installed at all.
			gpuMap, gpuErr := s.metrics.FetchAverage(ctx, "CWAgent", "utilization_gpu", "InstanceId", runningIDs, cfg.IdleDays)
			if gpuErr != nil {
				slog.Warn("Failed to fetch EC2 GPU metrics", "region", s.region, "error", gpuErr)
				gpuMap = make(map[string]float64)
			}

			// Fetch per-day CPU maxima for burst detection (WO-247): a flat
			// CPU *average* structurally cannot see a periodic cron/batch/CI
			// workload that spikes CPU at a consistent hour each day but sits
			// near-idle the rest of the time. Optional — on failure the burst
			// check is simply skipped, falling back to average-only behavior.
			burstThreshold := cfg.IdleCPUBurstThreshold
			if burstThreshold <= 0 {
				burstThreshold = defaultIdleCPUBurstThreshold
			}
			dailyMaxMap, dailyMaxErr := s.metrics.FetchDailyMaximum(ctx, "AWS/EC2", "CPUUtilization", "InstanceId", runningIDs, cfg.IdleDays)
			if dailyMaxErr != nil {
				slog.Warn("Failed to fetch EC2 daily CPU maxima for burst detection", "region", s.region, "error", dailyMaxErr)
				dailyMaxMap = make(map[string][]float64)
			}

			instanceMap := buildInstanceMap(instances)
			for _, id := range runningIDs {
				avgCPU, ok := cpuMap[id]
				if !ok {
					continue
				}
				if avgCPU < cfg.IdleCPUThreshold {
					inst := instanceMap[id]
					instanceType := string(inst.InstanceType)

					// A GPU-bound instance with low CPU may still be fully saturated
					// on the GPU itself — no GPU metric data means the CloudWatch
					// agent's GPU plugin isn't installed, so fall back to CPU-only.
					// Deliberately reuses cfg.HighMemoryThreshold rather than adding a
					// second threshold flag: both checks answer "is some other
					// utilization signal above the configured high-utilization bar,"
					// so --high-memory-threshold doubles as the GPU bar too.
					avgGPU, hasGPU := gpuMap[id]
					if isGPUInstanceType(instanceType) && hasGPU && avgGPU >= cfg.HighMemoryThreshold {
						slog.Debug("GPU instance has low CPU but high GPU utilization — not idle",
							"instance", id, "cpu", avgCPU, "gpu", avgGPU)
						continue
					}

					// Check if memory utilization is high enough to override the idle CPU signal
					avgMem, hasMem := memMap[id]
					if hasMem && avgMem >= cfg.HighMemoryThreshold {
						slog.Debug("Instance has low CPU but high memory — not idle",
							"instance", id, "cpu", avgCPU, "memory", avgMem)
						continue
					}

					cost := pricing.MonthlyEC2Cost(instanceType, s.region)
					window, sufficient := idleWindowDescription(cfg.IdleDays, inst.LaunchTime, now)
					metadata := map[string]any{
						"instance_type":      instanceType,
						"avg_cpu_percent":    avgCPU,
						"avg_mem_percent":    avgMem,
						"has_mem_metrics":    hasMem,
						"state":              "running",
						"sufficient_history": sufficient,
					}
					if isGPUInstanceType(instanceType) {
						metadata["avg_gpu_percent"] = avgGPU
						metadata["has_gpu_metrics"] = hasGPU
					}

					severity := SeverityHigh
					remediationPath := RemediationDirect
					msg := idleMessage(avgCPU, avgMem, hasMem, window)
					if isNodeGroupManagedEC2(ec2TagsToMap(inst.Tags)) {
						// WO-239: node-group-managed instances are scaled by
						// their owning EKS node group or Auto Scaling Group —
						// down-rank and correct the guidance instead of
						// suggesting direct termination, mirroring WO-220's
						// ELB precedent.
						severity = SeverityMedium
						remediationPath = RemediationViaController
						msg = fmt.Sprintf("%s — managed by an EKS/Auto Scaling Group node group; scale down via that node group instead of terminating the instance directly", msg)
						metadata["node_group_managed"] = true
					}

					// WO-247: a low CPU average with recurring daily max spikes
					// is evidence of periodic/scheduled activity (cron, batch,
					// CI), not continuous idleness — disclose the burst signal
					// and weaken the idle verdict rather than presenting a flat
					// average as if it were continuous idleness. Composes under
					// node-group: burst only adds metadata + an annotation and
					// never overrides an already-down-ranked severity or a
					// more-specific via_controller remediation path.
					//
					// WO-254: gated on `sufficient` running history. CloudWatch
					// Period=86400 buckets align to UTC midnight, so a young
					// instance's partial-day buckets can read as false spike
					// days (boot/deploy noise), and the X/Y-days denominator is
					// misleading when Y < the configured window. Skip burst
					// detection entirely for insufficient history — the
					// idleWindowDescription message already discloses the gap.
					if sufficient {
						if spikeDays, peakMax, ok := detectCPUBurst(dailyMaxMap[id], burstThreshold); ok {
							metadata["burst_cpu_days"] = spikeDays
							metadata["burst_cpu_peak_percent"] = peakMax
							metadata["burst_threshold_percent"] = burstThreshold
							msg = fmt.Sprintf("%s — daily CPU max reached %.0f%% on %d/%d days (periodic/scheduled activity suspected; review before terminating)", msg, peakMax, spikeDays, len(dailyMaxMap[id]))
							if severity == SeverityHigh {
								severity = SeverityMedium
							}
							if remediationPath == RemediationDirect {
								remediationPath = RemediationNeedsReview
							}
						}
					}

					result.Findings = append(result.Findings, Finding{
						ID:                    FindingIdleEC2,
						Severity:              severity,
						ResourceType:          ResourceEC2,
						ResourceID:            id,
						ResourceName:          instanceName(inst),
						Region:                s.region,
						Message:               msg,
						EstimatedMonthlyWaste: cost,
						RemediationPath:       remediationPath,
						Metadata:              metadata,
					})
				}
			}
		}
	}

	return result, nil
}

func (s *EC2Scanner) listInstances(ctx context.Context) ([]ec2types.Instance, error) {
	var instances []ec2types.Instance
	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("instance-state-name"),
				Values: []string{"running", "stopped"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, res := range page.Reservations {
			instances = append(instances, res.Instances...)
		}
	}
	return instances, nil
}

func (s *EC2Scanner) enrichStoppedWithEBSCost(ctx context.Context, result *ScanResult, stoppedVolumeIDs map[string][]string) {
	// Collect all volume IDs across all stopped instances
	var allVolIDs []string
	for _, vids := range stoppedVolumeIDs {
		allVolIDs = append(allVolIDs, vids...)
	}
	if len(allVolIDs) == 0 {
		return
	}

	volDetails, err := s.describeVolumesByIDs(ctx, allVolIDs)
	if err != nil {
		slog.Warn("Failed to fetch EBS volumes for stopped instances", "region", s.region, "error", err)
		return
	}

	for i, f := range result.Findings {
		if f.ID != FindingStoppedEC2 {
			continue
		}
		vids := stoppedVolumeIDs[f.ResourceID]
		if len(vids) == 0 {
			continue
		}

		var ebsCost float64
		var volSummary []map[string]any
		for _, vid := range vids {
			v, ok := volDetails[vid]
			if !ok {
				continue
			}
			cost := pricing.MonthlyEBSCost(v.volumeType, v.sizeGiB, s.region)
			ebsCost += cost
			volSummary = append(volSummary, map[string]any{
				"volume_id":    vid,
				"volume_type":  v.volumeType,
				"size_gib":     v.sizeGiB,
				"monthly_cost": cost,
			})
		}

		result.Findings[i].EstimatedMonthlyWaste = ebsCost
		result.Findings[i].Metadata["ebs_monthly_cost"] = ebsCost
		result.Findings[i].Metadata["attached_volumes"] = volSummary
		if ebsCost > 0 {
			daysStopped := result.Findings[i].Metadata["days_stopped"]
			result.Findings[i].Message = fmt.Sprintf("Stopped for %v days, %d attached volumes ($%.2f/month EBS)", daysStopped, len(volSummary), ebsCost)
		}
	}
}

type ebsVolumeInfo struct {
	volumeType string
	sizeGiB    int
}

func (s *EC2Scanner) describeVolumesByIDs(ctx context.Context, volumeIDs []string) (map[string]ebsVolumeInfo, error) {
	out, err := s.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: volumeIDs,
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string]ebsVolumeInfo, len(out.Volumes))
	for _, vol := range out.Volumes {
		if vol.VolumeId != nil {
			result[*vol.VolumeId] = ebsVolumeInfo{
				volumeType: string(vol.VolumeType),
				sizeGiB:    int(derefInt32(vol.Size)),
			}
		}
	}
	return result, nil
}

func instanceName(inst ec2types.Instance) string {
	return tagValue(inst.Tags, "Name")
}

// stoppedSince returns the LaunchTime-based fallback estimate for when an
// instance was stopped. Scan() prefers a real CloudTrail StopInstances event
// over this estimate when one is available — WO-243.
func stoppedSince(inst ec2types.Instance) time.Time {
	if inst.LaunchTime != nil {
		return *inst.LaunchTime
	}
	return time.Time{}
}

func idleMessage(avgCPU, avgMem float64, hasMem bool, window string) string {
	if hasMem {
		return fmt.Sprintf("CPU %.1f%%, memory %.1f%% over %s", avgCPU, avgMem, window)
	}
	return fmt.Sprintf("CPU %.1f%% over %s", avgCPU, window)
}

// idleWindowDescription and formatDuration moved to idlewindow.go — WO-249
// generalized this pattern beyond EC2 to the rest of the resource family
// (WO-237 surveyed which scanners the pattern applies to).

// gpuInstanceFamilyPrefixes are the family prefixes AWS uses for GPU/accelerator
// instance types (the part before the size suffix, e.g. "g4dn" in "g4dn.xlarge").
// Prefix matching (not exact) intentionally also covers variants not spelled out
// here, e.g. "p4d"/"p4de" via "p4", "g4ad" via "g4" — WO-235.
var gpuInstanceFamilyPrefixes = []string{"p2", "p3", "p4", "p5", "g3", "g4", "g5", "g6", "inf1", "inf2", "trn1"}

func isGPUInstanceType(instanceType string) bool {
	family := instanceType
	if idx := strings.Index(instanceType, "."); idx >= 0 {
		family = instanceType[:idx]
	}
	for _, prefix := range gpuInstanceFamilyPrefixes {
		if strings.HasPrefix(family, prefix) {
			return true
		}
	}
	return false
}

func buildInstanceMap(instances []ec2types.Instance) map[string]ec2types.Instance {
	m := make(map[string]ec2types.Instance, len(instances))
	for _, inst := range instances {
		if inst.InstanceId != nil {
			m[*inst.InstanceId] = inst
		}
	}
	return m
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
