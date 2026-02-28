package aws

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"log/slog"
)

// LambdaAPI is the minimal interface for Lambda operations.
type LambdaAPI interface {
	ListFunctions(ctx context.Context, input *lambda.ListFunctionsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// LambdaScanner detects Lambda functions with zero invocations.
type LambdaScanner struct {
	client  LambdaAPI
	metrics *MetricsFetcher
	region  string
}

// NewLambdaScanner creates a scanner for Lambda functions.
func NewLambdaScanner(client LambdaAPI, metrics *MetricsFetcher, region string) *LambdaScanner {
	return &LambdaScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *LambdaScanner) Type() ResourceType {
	return ResourceLambda
}

// Scan examines all Lambda functions for zero invocations over the idle window.
func (s *LambdaScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	functions, err := s.listFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Lambda functions: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(functions)}
	if len(functions) == 0 {
		return result, nil
	}

	// Collect names for CloudWatch lookup
	var names []string
	fnMap := make(map[string]lambdatypes.FunctionConfiguration, len(functions))
	for _, fn := range functions {
		name := deref(fn.FunctionName)
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}
		names = append(names, name)
		fnMap[name] = fn
	}

	if len(names) == 0 {
		return result, nil
	}

	invocations, err := s.metrics.FetchSum(ctx, "AWS/Lambda", "Invocations", "FunctionName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch Lambda metrics", "region", s.region, "error", err)
		return result, nil
	}

	for _, name := range names {
		if invocations[name] > 0 {
			continue
		}

		fn := fnMap[name]
		meta := map[string]any{
			"runtime":         string(fn.Runtime),
			"code_size_bytes": fn.CodeSize,
			"last_modified":   deref(fn.LastModified),
		}
		if fn.MemorySize != nil {
			meta["memory_mb"] = *fn.MemorySize
		}
		if fn.Timeout != nil {
			meta["timeout_sec"] = *fn.Timeout
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingIdleLambda,
			Severity:              SeverityLow,
			ResourceType:          ResourceLambda,
			ResourceID:            name,
			ResourceName:          deref(fn.FunctionArn),
			Region:                s.region,
			Message:               fmt.Sprintf("Zero invocations over %d days", cfg.IdleDays),
			EstimatedMonthlyWaste: 0,
			Metadata:              meta,
		})
	}

	return result, nil
}

func (s *LambdaScanner) listFunctions(ctx context.Context) ([]lambdatypes.FunctionConfiguration, error) {
	var functions []lambdatypes.FunctionConfiguration
	paginator := lambda.NewListFunctionsPaginator(s.client, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		functions = append(functions, page.Functions...)
	}
	return functions, nil
}
