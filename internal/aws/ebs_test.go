package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
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

func TestEBSScanner_Type(t *testing.T) {
	scanner := &EBSScanner{}
	if scanner.Type() != ResourceEBS {
		t.Fatalf("expected ResourceEBS, got %s", scanner.Type())
	}
}
