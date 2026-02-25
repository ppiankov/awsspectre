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

func TestEBSScanner_Type(t *testing.T) {
	scanner := &EBSScanner{}
	if scanner.Type() != ResourceEBS {
		t.Fatalf("expected ResourceEBS, got %s", scanner.Type())
	}
}
