package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockSnapshotClient struct {
	snapshots []ec2types.Snapshot
	images    []ec2types.Image
}

func (m *mockSnapshotClient) DescribeSnapshots(_ context.Context, _ *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return &ec2.DescribeSnapshotsOutput{Snapshots: m.snapshots}, nil
}

func (m *mockSnapshotClient) DescribeImages(_ context.Context, _ *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return &ec2.DescribeImagesOutput{Images: m.images}, nil
}

func TestSnapshotScanner_StaleSnapshot(t *testing.T) {
	startTime := time.Now().UTC().Add(-120 * 24 * time.Hour) // 120 days ago
	mock := &mockSnapshotClient{
		snapshots: []ec2types.Snapshot{
			{
				SnapshotId:  awssdk.String("snap-stale001"),
				VolumeId:    awssdk.String("vol-src001"),
				VolumeSize:  awssdk.Int32(50),
				StartTime:   &startTime,
				Description: awssdk.String("Old backup"),
			},
		},
		images: nil, // no AMIs
	}

	scanner := NewSnapshotScanner(mock, "us-east-1")
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
	if f.ID != FindingStaleSnapshot {
		t.Fatalf("expected STALE_SNAPSHOT, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestSnapshotScanner_RecentSnapshotNotFlagged(t *testing.T) {
	startTime := time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago
	mock := &mockSnapshotClient{
		snapshots: []ec2types.Snapshot{
			{
				SnapshotId: awssdk.String("snap-recent001"),
				VolumeSize: awssdk.Int32(50),
				StartTime:  &startTime,
			},
		},
	}

	scanner := NewSnapshotScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for recent snapshot, got %d", len(result.Findings))
	}
}

func TestSnapshotScanner_AMIReferencedNotFlagged(t *testing.T) {
	startTime := time.Now().UTC().Add(-120 * 24 * time.Hour)
	mock := &mockSnapshotClient{
		snapshots: []ec2types.Snapshot{
			{
				SnapshotId: awssdk.String("snap-ami001"),
				VolumeSize: awssdk.Int32(50),
				StartTime:  &startTime,
			},
		},
		images: []ec2types.Image{
			{
				ImageId: awssdk.String("ami-001"),
				BlockDeviceMappings: []ec2types.BlockDeviceMapping{
					{
						Ebs: &ec2types.EbsBlockDevice{
							SnapshotId: awssdk.String("snap-ami001"),
						},
					},
				},
			},
		},
	}

	scanner := NewSnapshotScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for AMI-referenced snapshot, got %d", len(result.Findings))
	}
}

func TestSnapshotScanner_NoSnapshots(t *testing.T) {
	mock := &mockSnapshotClient{snapshots: nil}
	scanner := NewSnapshotScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestSnapshotScanner_ExcludedSnapshot(t *testing.T) {
	startTime := time.Now().UTC().Add(-120 * 24 * time.Hour)
	mock := &mockSnapshotClient{
		snapshots: []ec2types.Snapshot{
			{
				SnapshotId: awssdk.String("snap-excluded001"),
				VolumeSize: awssdk.Int32(50),
				StartTime:  &startTime,
			},
		},
	}

	scanner := NewSnapshotScanner(mock, "us-east-1")
	cfg := ScanConfig{
		StaleDays: 90,
		Exclude:   ExcludeConfig{ResourceIDs: map[string]bool{"snap-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded snapshot, got %d", len(result.Findings))
	}
}

func TestSnapshotScanner_Type(t *testing.T) {
	scanner := &SnapshotScanner{}
	if scanner.Type() != ResourceSnapshot {
		t.Fatalf("expected ResourceSnapshot, got %s", scanner.Type())
	}
}
