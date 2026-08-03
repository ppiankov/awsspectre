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
	ListTags(ctx context.Context, input *lambda.ListTagsInput, opts ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
	ListEventSourceMappings(ctx context.Context, input *lambda.ListEventSourceMappingsInput, opts ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error)
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
		tags, err := s.fetchTags(ctx, deref(fn.FunctionArn))
		if err != nil {
			slog.Warn("Failed to fetch Lambda function tags", "function", name, "error", err)
			tags = nil
		}
		if cfg.Exclude.ShouldExclude(name, tags) {
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

		severity := SeverityLow
		remediationPath := RemediationDirect
		msg := fmt.Sprintf("Zero invocations over %d days", cfg.IdleDays)

		// WO-246: a Lambda with zero invocations may still have a
		// legitimate, infrequent trigger — a CFN custom resource
		// (stack lifecycle events only) or a live event source
		// (SQS/DynamoDB/Kinesis stream) that fires rarely. Down-rank
		// and annotate rather than presenting as genuinely orphaned.
		tags, tagErr := s.fetchTags(ctx, deref(fn.FunctionArn))
		if tagErr != nil {
			slog.Warn("Failed to fetch Lambda tags for rare-trigger check", "function", name, "error", tagErr)
			tags = nil
		}
		hasSource, sourceErr := s.hasEventSource(ctx, name)
		if sourceErr != nil {
			slog.Warn("Failed to check Lambda event sources", "function", name, "error", sourceErr)
		}

		if _, isCFN := tags["aws:cloudformation:logical-id"]; isCFN {
			severity = SeverityMedium
			remediationPath = RemediationNeedsReview
			msg = fmt.Sprintf("%s — CloudFormation custom resource (invoked only at stack lifecycle events; review stack before deleting)", msg)
			meta["cfn_custom_resource"] = true
		} else if hasSource {
			severity = SeverityMedium
			remediationPath = RemediationNeedsReview
			msg = fmt.Sprintf("%s — has a live event source but zero recent invocations (infrequent-but-wired, not genuinely orphaned; review before deleting)", msg)
			meta["has_event_source"] = true
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingIdleLambda,
			Severity:              severity,
			ResourceType:          ResourceLambda,
			ResourceID:            name,
			ResourceName:          deref(fn.FunctionArn),
			Region:                s.region,
			Message:               msg,
			EstimatedMonthlyWaste: 0,
			Hygiene:               true,
			RemediationPath:       remediationPath,
			Metadata:              meta,
		})
	}

	return result, nil
}

// fetchTags fetches all tags for a Lambda function (Lambda's ListTags has no
// pagination and no bulk/batched variant).
func (s *LambdaScanner) fetchTags(ctx context.Context, functionARN string) (map[string]string, error) {
	if functionARN == "" {
		return nil, nil
	}
	out, err := s.client.ListTags(ctx, &lambda.ListTagsInput{Resource: &functionARN})
	if err != nil {
		return nil, err
	}
	return out.Tags, nil
}

// hasEventSource returns true if the function has at least one event source
// mapping (SQS, DynamoDB, Kinesis, etc.) — a live trigger that fires
// infrequently, not a genuinely orphaned function. WO-246.
func (s *LambdaScanner) hasEventSource(ctx context.Context, functionName string) (bool, error) {
	out, err := s.client.ListEventSourceMappings(ctx, &lambda.ListEventSourceMappingsInput{
		FunctionName: &functionName,
	})
	if err != nil {
		return false, err
	}
	return len(out.EventSourceMappings) > 0, nil
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
