package aws

import (
	"context"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEBSClient struct {
	volumes []ec2types.Volume
}

func (m *mockEBSClient) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: m.volumes}, nil
}

func TestEBSScanner_DetachedVolume(t *testing.T) {
	created := time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:         awssdk.String("vol-detached001"),
				VolumeType:       ec2types.VolumeTypeGp3,
				State:            ec2types.VolumeStateAvailable,
				Size:             awssdk.Int32(100),
				CreateTime:       &created,
				AvailabilityZone: awssdk.String("us-east-1a"),
				Tags:             []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("old-data")}},
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingDetachedEBS {
		t.Fatalf("expected DETACHED_EBS, got %s", f.ID)
	}
	if f.ResourceID != "vol-detached001" {
		t.Fatalf("expected vol-detached001, got %s", f.ResourceID)
	}
	if f.ResourceName != "old-data" {
		t.Fatalf("expected name old-data, got %s", f.ResourceName)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestEBSScanner_RecentlyCreatedNotFlagged(t *testing.T) {
	created := time.Now().UTC().Add(-3 * 24 * time.Hour) // 3 days ago
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-recent001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(50),
				CreateTime: &created,
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for recently created volume, got %d", len(result.Findings))
	}
}

func TestEBSScanner_NoVolumes(t *testing.T) {
	mock := &mockEBSClient{volumes: nil}
	scanner := NewEBSScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestEBSScanner_ExcludedVolume(t *testing.T) {
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-excluded001"),
				VolumeType: ec2types.VolumeTypeGp3,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	cfg := ScanConfig{
		Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"vol-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded volume, got %d", len(result.Findings))
	}
}

func TestEBSScanner_Gp2VolumeFlaggedAsMigrationCandidate(t *testing.T) {
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-gp2001"),
				VolumeType: ec2types.VolumeTypeGp2,
				State:      ec2types.VolumeStateInUse,
				Size:       awssdk.Int32(100),
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingGP2MigrationCandidate {
		t.Fatalf("expected GP2_MIGRATION_CANDIDATE, got %s", f.ID)
	}
	if f.EstimatedMonthlyWaste <= 0 {
		t.Fatalf("expected positive gp2/gp3 savings estimate, got %f", f.EstimatedMonthlyWaste)
	}
	if !f.Hygiene {
		// Regression: a live dogfood run found 11 real gp2 volumes in an account,
		// but only 1 survived the default --min-monthly-cost filter because
		// per-volume savings are often a few cents to a couple dollars/month.
		t.Fatal("expected GP2_MIGRATION_CANDIDATE to be Hygiene-visible regardless of --min-monthly-cost")
	}
	if remediation, _ := f.Metadata["remediation"].(string); remediation != "aws ec2 modify-volume --volume-id vol-gp2001 --volume-type gp3" {
		t.Fatalf("unexpected remediation command: %q", remediation)
	}
}

func TestEBSScanner_Gp2VolumeInTransitionalStateNotFlagged(t *testing.T) {
	// aws ec2 modify-volume only accepts available or in-use volumes; a gp2
	// volume still creating, deleting, or in error state must not be flagged,
	// since the emitted remediation command would be rejected by AWS.
	for _, state := range []ec2types.VolumeState{ec2types.VolumeStateCreating, ec2types.VolumeStateDeleting, ec2types.VolumeStateError} {
		mock := &mockEBSClient{
			volumes: []ec2types.Volume{
				{
					VolumeId:   awssdk.String("vol-gp2transitional"),
					VolumeType: ec2types.VolumeTypeGp2,
					State:      state,
					Size:       awssdk.Int32(100),
				},
			},
		}

		scanner := NewEBSScanner(mock, "us-east-1")
		result, err := scanner.Scan(context.Background(), ScanConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("state %s: expected no findings for a gp2 volume that can't be modified, got %d", state, len(result.Findings))
		}
	}
}

func TestEBSScanner_Gp3VolumeNotFlaggedAsMigrationCandidate(t *testing.T) {
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-gp3001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateInUse,
				Size:       awssdk.Int32(100),
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for gp3 volume, got %d", len(result.Findings))
	}
}

func TestEBSScanner_DetachedGp2VolumeProducesBothFindings(t *testing.T) {
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-detachedgp2"),
				VolumeType: ec2types.VolumeTypeGp2,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(50),
				CreateTime: &created,
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings (detached + gp2 migration), got %d", len(result.Findings))
	}

	var sawDetached, sawGp2 bool
	for _, f := range result.Findings {
		switch f.ID {
		case FindingDetachedEBS:
			sawDetached = true
		case FindingGP2MigrationCandidate:
			sawGp2 = true
		}
	}
	if !sawDetached || !sawGp2 {
		t.Fatalf("expected both DETACHED_EBS and GP2_MIGRATION_CANDIDATE findings, got %+v", result.Findings)
	}
}

func TestEBSScanner_ExcludedGp2VolumeNotFlagged(t *testing.T) {
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-gp2excluded"),
				VolumeType: ec2types.VolumeTypeGp2,
				State:      ec2types.VolumeStateInUse,
				Size:       awssdk.Int32(100),
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	cfg := ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"vol-gp2excluded": true}}}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded gp2 volume, got %d", len(result.Findings))
	}
}

func TestEBSScanner_DetachedVolume_UsesCloudTrailDetachTime(t *testing.T) {
	// WO-242: a live dogfood account showed a volume created 382 days ago but
	// with a real CloudTrail DetachVolume event only ~3 days before the scan
	// (it had been attached and cycling for most of that time). Using
	// CreateTime alone would wrongly flag it; the CloudTrail event correctly
	// shows it hasn't been detached long enough to cross the threshold.
	created := time.Now().UTC().Add(-382 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-cycling001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
			},
		},
	}
	recentDetach := time.Now().UTC().Add(-3 * 24 * time.Hour)
	ct := &mockCloudTrailClient{events: []cttypes.Event{newMockEvent("DetachVolume", recentDetach)}}

	scanner := NewEBSScanner(mock, "us-east-1")
	scanner.SetCloudTrailClient(ct)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no DETACHED_EBS finding — real detach was only 3 days ago, below the 7-day threshold, got %d findings", len(result.Findings))
	}
}

func TestEBSScanner_DetachedVolume_AboveThreshold_UsesCloudTrailDayCount(t *testing.T) {
	// WO-242: a live dogfood account showed a volume created ~100 days ago
	// with a real CloudTrail DetachVolume event ~90 days before the scan —
	// still above the 7-day threshold either way, so the finding fires in
	// both cases, but the reported days_detached must reflect the more
	// accurate CloudTrail-derived value (90), not the CreateTime-derived one
	// (100).
	created := time.Now().UTC().Add(-100 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-aboveThreshold001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
			},
		},
	}
	detachTime := time.Now().UTC().Add(-90 * 24 * time.Hour)
	ct := &mockCloudTrailClient{events: []cttypes.Event{newMockEvent("DetachVolume", detachTime)}}

	scanner := NewEBSScanner(mock, "us-east-1")
	scanner.SetCloudTrailClient(ct)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if days, _ := result.Findings[0].Metadata["days_detached"].(int); days < 89 || days > 91 {
		t.Fatalf("expected days_detached ~90 from CloudTrail (not ~100 from CreateTime), got %v", result.Findings[0].Metadata["days_detached"])
	}
}

func TestEBSScanner_DetachedVolume_CloudTrailNoMatch_FallsBackToCreateTime(t *testing.T) {
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-nomatch001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
			},
		},
	}
	ct := &mockCloudTrailClient{events: nil} // no matching event found

	scanner := NewEBSScanner(mock, "us-east-1")
	scanner.SetCloudTrailClient(ct)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected fallback to CreateTime-based detection, got %d findings", len(result.Findings))
	}
	if days, _ := result.Findings[0].Metadata["days_detached"].(int); days < 29 || days > 31 {
		t.Fatalf("expected days_detached ~30 from CreateTime fallback, got %v", result.Findings[0].Metadata["days_detached"])
	}
}

func TestEBSScanner_CSIManagedVolume_WithPVCInfo_AnnotatedGuidance(t *testing.T) {
	// WO-231: same defect class as WO-220 for load balancers. A detached
	// volume carrying AWS EBS CSI driver tags must keep the finding visible
	// (it can still be genuine waste) but correct the guidance to verify via
	// kubectl before deleting directly, naming the PVC/namespace from tags.
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-csimanaged001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
				Tags: []ec2types.Tag{
					{Key: awssdk.String("kubernetes.io/created-for/pvc/name"), Value: awssdk.String("data-pvc")},
					{Key: awssdk.String("kubernetes.io/created-for/pvc/namespace"), Value: awssdk.String("platform")},
					{Key: awssdk.String("ebs.csi.aws.com/cluster"), Value: awssdk.String("true")},
				},
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the finding to still surface (evidence, not suppressed), got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityHigh {
		t.Fatalf("expected severity to remain high (still visible waste), got %s", f.Severity)
	}
	if !strings.Contains(f.Message, `PVC "data-pvc" in namespace "platform"`) {
		t.Fatalf("expected message to name the PVC and namespace, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "kubectl get pv") {
		t.Fatalf("expected message to advise verifying with kubectl before deleting, got %q", f.Message)
	}
	if f.Metadata["csi_managed"] != true {
		t.Fatalf("expected csi_managed=true in metadata, got %v", f.Metadata["csi_managed"])
	}
	if f.Metadata["pvc_name"] != "data-pvc" || f.Metadata["pvc_namespace"] != "platform" {
		t.Fatalf("expected pvc_name/pvc_namespace in metadata, got %v", f.Metadata)
	}
	if f.RemediationPath != RemediationNeedsReview {
		t.Fatalf("expected RemediationPath=needs_review for a CSI-managed volume, got %q", f.RemediationPath)
	}
}

func TestEBSScanner_CSIManagedVolume_ClusterTagOnly_GenericGuidance(t *testing.T) {
	// A volume with only the CSI cluster tag (no PVC name/namespace tags)
	// still gets the corrected generic guidance, without naming a PVC it
	// doesn't have information about.
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-csiclusteronly001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
				Tags: []ec2types.Tag{
					{Key: awssdk.String("ebs.csi.aws.com/cluster"), Value: awssdk.String("true")},
				},
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if !strings.Contains(f.Message, "provisioned by a Kubernetes PersistentVolume") {
		t.Fatalf("expected generic Kubernetes-managed guidance, got %q", f.Message)
	}
	if strings.Contains(f.Message, "PVC ") {
		t.Fatalf("expected no PVC name mentioned when tags don't provide one, got %q", f.Message)
	}
	if _, ok := f.Metadata["pvc_name"]; ok {
		t.Fatalf("expected no pvc_name metadata key when the tag isn't present, got %v", f.Metadata["pvc_name"])
	}
	if f.RemediationPath != RemediationNeedsReview {
		t.Fatalf("expected RemediationPath=needs_review, got %q", f.RemediationPath)
	}
}

func TestEBSScanner_CSIManagedVolume_PVCTagsOnly_NoClusterTag(t *testing.T) {
	// The older in-tree AWS EBS provisioner sets the kubernetes.io/created-for/*
	// tags without necessarily also setting the CSI-driver-specific
	// ebs.csi.aws.com/cluster tag. This must be recognized on its own, not
	// only when paired with the cluster tag.
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-intreeprovisioner001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
				Tags: []ec2types.Tag{
					{Key: awssdk.String("kubernetes.io/created-for/pvc/name"), Value: awssdk.String("legacy-pvc")},
					{Key: awssdk.String("kubernetes.io/created-for/pvc/namespace"), Value: awssdk.String("legacy-ns")},
				},
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if !strings.Contains(f.Message, `PVC "legacy-pvc" in namespace "legacy-ns"`) {
		t.Fatalf("expected message to name the PVC/namespace from in-tree-provisioner tags alone, got %q", f.Message)
	}
	if f.Metadata["csi_managed"] != true {
		t.Fatalf("expected csi_managed=true without the cluster tag present, got %v", f.Metadata["csi_managed"])
	}
	if f.RemediationPath != RemediationNeedsReview {
		t.Fatalf("expected RemediationPath=needs_review, got %q", f.RemediationPath)
	}
}

func TestEBSScanner_NonCSIVolume_UnchangedMessageAndRemediation(t *testing.T) {
	// A plain detached volume with no CSI tags must be completely unaffected
	// by this fix — same message shape, same RemediationPath default as
	// before WO-231.
	created := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mock := &mockEBSClient{
		volumes: []ec2types.Volume{
			{
				VolumeId:   awssdk.String("vol-plain001"),
				VolumeType: ec2types.VolumeTypeGp3,
				State:      ec2types.VolumeStateAvailable,
				Size:       awssdk.Int32(100),
				CreateTime: &created,
				Tags:       []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("plain-volume")}},
			},
		},
	}

	scanner := NewEBSScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Message != "Detached 30 days, gp3 100 GiB" {
		t.Fatalf("expected unchanged message for a non-CSI volume, got %q", f.Message)
	}
	if _, ok := f.Metadata["csi_managed"]; ok {
		t.Fatalf("expected no csi_managed metadata key for a non-CSI volume, got %v", f.Metadata["csi_managed"])
	}
	if f.EffectiveRemediationPath() != RemediationDirect {
		t.Fatalf("expected RemediationPath to resolve to direct for a non-CSI volume, got %q", f.EffectiveRemediationPath())
	}
}

func TestEBSScanner_Type(t *testing.T) {
	scanner := &EBSScanner{}
	if scanner.Type() != ResourceEBS {
		t.Fatalf("expected ResourceEBS, got %s", scanner.Type())
	}
}
