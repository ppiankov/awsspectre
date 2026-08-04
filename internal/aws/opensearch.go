package aws

import (
	"context"
	"fmt"
	"github.com/ppiankov/awsspectre/internal/pricing"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

// OpenSearchAPI is the minimal interface for OpenSearch operations.
type OpenSearchAPI interface {
	ListDomainNames(ctx context.Context, input *opensearch.ListDomainNamesInput, opts ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomain(ctx context.Context, input *opensearch.DescribeDomainInput, opts ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

// OpenSearchScanner detects idle OpenSearch domains.
type OpenSearchScanner struct {
	client  OpenSearchAPI
	metrics *MetricsFetcher
	region  string
}

// NewOpenSearchScanner creates a scanner for OpenSearch domains.
func NewOpenSearchScanner(client OpenSearchAPI, metrics *MetricsFetcher, region string) *OpenSearchScanner {
	return &OpenSearchScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *OpenSearchScanner) Type() ResourceType {
	return ResourceOpenSearch
}

// Scan examines all OpenSearch domains for idle activity.
func (s *OpenSearchScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	names, err := s.listDomainNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("list OpenSearch domains: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(names)}
	if len(names) == 0 {
		return result, nil
	}

	searchRate, err := s.metrics.FetchSum(ctx, "AWS/ES", "SearchRate", "DomainName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch OpenSearch SearchRate metrics", "region", s.region, "error", err)
		return result, nil
	}

	indexRate, err := s.metrics.FetchSum(ctx, "AWS/ES", "IndexingRate", "DomainName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch OpenSearch IndexingRate metrics", "region", s.region, "error", err)
		return result, nil
	}

	for _, name := range names {
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}
		if searchRate[name] > 0 || indexRate[name] > 0 {
			continue
		}

		cost := 0.0
		meta := map[string]any{}
		desc, err := s.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &name})
		if err != nil {
			slog.Warn("Failed to describe OpenSearch domain", "domain", name, "error", err)
		} else if ds := desc.DomainStatus; ds != nil {
			if cc := ds.ClusterConfig; cc != nil {
				it := string(cc.InstanceType)
				cnt := 1
				if cc.InstanceCount != nil {
					cnt = int(*cc.InstanceCount)
				}
				meta["instance_type"] = it
				meta["instance_count"] = cnt
				cost = pricing.MonthlyOpenSearchCost(it, cnt, s.region)
			}
			if ev := ds.EngineVersion; ev != nil {
				meta["engine_version"] = *ev
			}
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingOpenSearchIdle,
			Severity:              SeverityHigh,
			ResourceType:          ResourceOpenSearch,
			ResourceID:            name,
			ResourceName:          name,
			Region:                s.region,
			Message:               fmt.Sprintf("Zero search and indexing activity over %d days", cfg.IdleDays),
			EstimatedMonthlyWaste: cost,
			Metadata:              meta,
		})
	}

	return result, nil
}

func (s *OpenSearchScanner) listDomainNames(ctx context.Context) ([]string, error) {
	out, err := s.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, dn := range out.DomainNames {
		if dn.DomainName != nil {
			names = append(names, *dn.DomainName)
		}
	}
	return names, nil
}
