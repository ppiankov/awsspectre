package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// defaultECRUntaggedThreshold is used when ScanConfig.ECRUntaggedThreshold is
// unset (zero value) — defensive fallback for direct ScanConfig construction;
// the CLI flag itself defaults to the same value.
const defaultECRUntaggedThreshold = 20

// ECRAPI is the minimal interface for ECR repository/image operations.
type ECRAPI interface {
	DescribeRepositories(ctx context.Context, input *ecr.DescribeRepositoriesInput, opts ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	GetLifecyclePolicy(ctx context.Context, input *ecr.GetLifecyclePolicyInput, opts ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	DescribeImages(ctx context.Context, input *ecr.DescribeImagesInput, opts ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

// ECRScanner detects ECR repositories with no lifecycle policy and
// repositories accumulating untagged image sprawl.
type ECRScanner struct {
	client ECRAPI
	region string
}

// NewECRScanner creates a scanner for ECR repositories.
func NewECRScanner(client ECRAPI, region string) *ECRScanner {
	return &ECRScanner{client: client, region: region}
}

// Type returns the resource type this scanner handles.
func (s *ECRScanner) Type() ResourceType {
	return ResourceECR
}

// Scan examines all ECR repositories for missing lifecycle policies and
// untagged-image storage sprawl.
func (s *ECRScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	repos, err := s.listRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ECR repositories: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(repos)}
	if len(repos) == 0 {
		return result, nil
	}

	threshold := cfg.ECRUntaggedThreshold
	if threshold <= 0 {
		threshold = defaultECRUntaggedThreshold
	}

	for _, repo := range repos {
		name := deref(repo.RepositoryName)
		// ECR repository tags require a separate ecr:ListTagsForResource call
		// this scanner doesn't make (kept out of scope — WO-225); tag-based
		// --exclude-tags therefore has no effect on ECR findings, only
		// resource-ID exclusion does.
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}

		hasPolicy, err := s.hasLifecyclePolicy(ctx, name)
		if err != nil {
			slog.Warn("Failed to check ECR lifecycle policy", "repository", name, "error", err)
		} else if !hasPolicy {
			result.Findings = append(result.Findings, Finding{
				ID:           FindingECRNoLifecyclePolicy,
				Severity:     SeverityLow,
				ResourceType: ResourceECR,
				ResourceID:   name,
				ResourceName: deref(repo.RepositoryArn),
				Region:       s.region,
				Message:      "No lifecycle policy configured — images accumulate indefinitely",
				Hygiene:      true,
				Metadata: map[string]any{
					"repository_uri": deref(repo.RepositoryUri),
				},
			})
		}

		untaggedCount, untaggedBytes, err := s.untaggedImageStats(ctx, name)
		if err != nil {
			slog.Warn("Failed to describe ECR images", "repository", name, "error", err)
			continue
		}
		if untaggedCount > threshold {
			cost := pricing.MonthlyECRStorageCost(untaggedBytes, s.region)
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingECRUntaggedImageSprawl,
				Severity:              SeverityMedium,
				ResourceType:          ResourceECR,
				ResourceID:            name,
				ResourceName:          deref(repo.RepositoryArn),
				Region:                s.region,
				Message:               fmt.Sprintf("%d untagged images (threshold %d), %s", untaggedCount, threshold, formatBytes(untaggedBytes)),
				EstimatedMonthlyWaste: cost,
				Metadata: map[string]any{
					"untagged_image_count": untaggedCount,
					"untagged_bytes":       untaggedBytes,
					"threshold":            threshold,
				},
			})
		}
	}

	return result, nil
}

func (s *ECRScanner) listRepositories(ctx context.Context) ([]ecrtypes.Repository, error) {
	var repos []ecrtypes.Repository
	var nextToken *string

	for {
		out, err := s.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		repos = append(repos, out.Repositories...)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return repos, nil
}

// hasLifecyclePolicy returns false (not an error) when the repository has no
// lifecycle policy configured — ECR signals this via
// LifecyclePolicyNotFoundException rather than an empty/nil response.
func (s *ECRScanner) hasLifecyclePolicy(ctx context.Context, repoName string) (bool, error) {
	_, err := s.client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: &repoName})
	if err == nil {
		return true, nil
	}
	var notFound *ecrtypes.LifecyclePolicyNotFoundException
	if errors.As(err, &notFound) {
		return false, nil
	}
	return false, err
}

// untaggedImageStats returns the count and total size (in bytes) of untagged
// images in a repository, using ECR's server-side UNTAGGED tag-status filter.
func (s *ECRScanner) untaggedImageStats(ctx context.Context, repoName string) (count int, totalBytes int64, err error) {
	var nextToken *string

	for {
		out, err := s.client.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: &repoName,
			Filter:         &ecrtypes.DescribeImagesFilter{TagStatus: ecrtypes.TagStatusUntagged},
			NextToken:      nextToken,
		})
		if err != nil {
			return 0, 0, err
		}
		for _, img := range out.ImageDetails {
			count++
			if img.ImageSizeInBytes != nil {
				totalBytes += *img.ImageSizeInBytes
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return count, totalBytes, nil
}

// formatBytes renders a byte count as a human-readable GiB string.
func formatBytes(bytes int64) string {
	gib := float64(bytes) / (1024 * 1024 * 1024)
	return fmt.Sprintf("%.2f GiB", gib)
}
