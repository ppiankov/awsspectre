package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type mockLambdaClient struct {
	functions []lambdatypes.FunctionConfiguration
}

func (m *mockLambdaClient) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: m.functions}, nil
}

func TestLambdaScanner_IdleFunction(t *testing.T) {
	mock := &mockLambdaClient{
		functions: []lambdatypes.FunctionConfiguration{
			{
				FunctionName: awssdk.String("idle-func"),
				FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:idle-func"),
				Runtime:      lambdatypes.RuntimePython312,
				CodeSize:     1024,
				MemorySize:   awssdk.Int32(128),
				Timeout:      awssdk.Int32(30),
				LastModified: awssdk.String("2025-01-01T00:00:00.000+0000"),
			},
		},
	}

	// Return zero invocations
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{0}},
				},
			}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewLambdaScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
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
	if f.ID != FindingIdleLambda {
		t.Fatalf("expected IDLE_LAMBDA, got %s", f.ID)
	}
	if f.ResourceID != "idle-func" {
		t.Fatalf("expected idle-func, got %s", f.ResourceID)
	}
	if f.Severity != SeverityLow {
		t.Fatalf("expected low severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected $0 waste, got %f", f.EstimatedMonthlyWaste)
	}
	if f.Metadata["runtime"] != "python3.12" {
		t.Fatalf("expected python3.12 runtime, got %v", f.Metadata["runtime"])
	}
	if f.Metadata["memory_mb"] != int32(128) {
		t.Fatalf("expected 128 memory_mb, got %v", f.Metadata["memory_mb"])
	}
	if f.Metadata["timeout_sec"] != int32(30) {
		t.Fatalf("expected 30 timeout_sec, got %v", f.Metadata["timeout_sec"])
	}
}

func TestLambdaScanner_ActiveFunction(t *testing.T) {
	mock := &mockLambdaClient{
		functions: []lambdatypes.FunctionConfiguration{
			{
				FunctionName: awssdk.String("active-func"),
				FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:active-func"),
				Runtime:      lambdatypes.RuntimeNodejs20x,
				CodeSize:     2048,
				MemorySize:   awssdk.Int32(256),
				Timeout:      awssdk.Int32(60),
			},
		},
	}

	// Return non-zero invocations
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{150.0},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewLambdaScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active function, got %d", len(result.Findings))
	}
}

func TestLambdaScanner_NoFunctions(t *testing.T) {
	mock := &mockLambdaClient{functions: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewLambdaScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestLambdaScanner_ExcludedFunction(t *testing.T) {
	mock := &mockLambdaClient{
		functions: []lambdatypes.FunctionConfiguration{
			{
				FunctionName: awssdk.String("excluded-func"),
				FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:excluded-func"),
				Runtime:      lambdatypes.RuntimePython312,
				CodeSize:     512,
			},
		},
	}

	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{0}},
				},
			}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewLambdaScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"excluded-func": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded function, got %d", len(result.Findings))
	}
}

func TestLambdaScanner_Type(t *testing.T) {
	scanner := &LambdaScanner{}
	if scanner.Type() != ResourceLambda {
		t.Fatalf("expected ResourceLambda, got %s", scanner.Type())
	}
}
