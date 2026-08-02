package aws

import (
	"context"
	"errors"
	"strconv"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type mockECRClient struct {
	repos              []ecrtypes.Repository
	repoPages          [][]ecrtypes.Repository
	describeReposCalls int

	// lifecyclePolicyMissing marks repos (by name) with no configured policy;
	// lifecyclePolicyErr marks repos whose policy check should fail with a
	// generic (non-NotFound) error.
	lifecyclePolicyMissing map[string]bool
	lifecyclePolicyErr     map[string]error

	// untaggedImages maps repo name -> untagged ImageDetail list returned in
	// a single page; untaggedImagePages maps repo name -> paginated pages.
	untaggedImages      map[string][]ecrtypes.ImageDetail
	untaggedImagePages  map[string][][]ecrtypes.ImageDetail
	describeImagesCalls map[string]int
	describeImagesErr   map[string]error
}

func (m *mockECRClient) DescribeRepositories(_ context.Context, input *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	m.describeReposCalls++
	if m.repoPages == nil {
		return &ecr.DescribeRepositoriesOutput{Repositories: m.repos}, nil
	}

	idx := 0
	if input.NextToken != nil {
		idx, _ = strconv.Atoi(*input.NextToken)
	}
	out := &ecr.DescribeRepositoriesOutput{Repositories: m.repoPages[idx]}
	if idx+1 < len(m.repoPages) {
		next := strconv.Itoa(idx + 1)
		out.NextToken = &next
	}
	return out, nil
}

func (m *mockECRClient) GetLifecyclePolicy(_ context.Context, input *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	name := *input.RepositoryName
	if err, ok := m.lifecyclePolicyErr[name]; ok {
		return nil, err
	}
	if m.lifecyclePolicyMissing[name] {
		return nil, &ecrtypes.LifecyclePolicyNotFoundException{Message: awssdk.String("no lifecycle policy configured")}
	}
	return &ecr.GetLifecyclePolicyOutput{LifecyclePolicyText: awssdk.String("{}")}, nil
}

func (m *mockECRClient) DescribeImages(_ context.Context, input *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	name := *input.RepositoryName
	if m.describeImagesCalls == nil {
		m.describeImagesCalls = map[string]int{}
	}
	m.describeImagesCalls[name]++

	if err, ok := m.describeImagesErr[name]; ok {
		return nil, err
	}

	if pages, ok := m.untaggedImagePages[name]; ok {
		idx := 0
		if input.NextToken != nil {
			idx, _ = strconv.Atoi(*input.NextToken)
		}
		out := &ecr.DescribeImagesOutput{ImageDetails: pages[idx]}
		if idx+1 < len(pages) {
			next := strconv.Itoa(idx + 1)
			out.NextToken = &next
		}
		return out, nil
	}

	return &ecr.DescribeImagesOutput{ImageDetails: m.untaggedImages[name]}, nil
}

func untaggedImagesOfSize(count int, sizeBytes int64) []ecrtypes.ImageDetail {
	images := make([]ecrtypes.ImageDetail, count)
	for i := range images {
		images[i] = ecrtypes.ImageDetail{ImageSizeInBytes: awssdk.Int64(sizeBytes)}
	}
	return images
}

func TestECRScanner_NoLifecyclePolicy_Flagged(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{
			{
				RepositoryName: awssdk.String("app-repo"),
				RepositoryArn:  awssdk.String("arn:aws:ecr:us-east-1:123456789012:repository/app-repo"),
				RepositoryUri:  awssdk.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/app-repo"),
			},
		},
		lifecyclePolicyMissing: map[string]bool{"app-repo": true},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 1 {
		t.Fatalf("expected 1 resource scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingECRNoLifecyclePolicy {
		t.Fatalf("expected ECR_NO_LIFECYCLE_POLICY, got %s", f.ID)
	}
	if f.ResourceType != ResourceECR {
		t.Fatalf("expected ResourceECR, got %s", f.ResourceType)
	}
	if f.ResourceID != "app-repo" {
		t.Fatalf("expected resource id app-repo, got %s", f.ResourceID)
	}
	if !f.Hygiene {
		t.Fatal("expected Hygiene=true — visibility must not depend on current cost")
	}
}

func TestECRScanner_WithLifecyclePolicy_NotFlagged(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{{RepositoryName: awssdk.String("managed-repo")}},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if f.ID == FindingECRNoLifecyclePolicy {
			t.Fatal("expected no ECR_NO_LIFECYCLE_POLICY finding for a repository with a policy configured")
		}
	}
}

func TestECRScanner_UntaggedImagesAboveThreshold_Flagged(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{
			{RepositoryName: awssdk.String("sprawl-repo"), RepositoryArn: awssdk.String("arn:aws:ecr:us-east-1:123456789012:repository/sprawl-repo")},
		},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"sprawl-repo": untaggedImagesOfSize(25, 1024*1024*1024), // 25 x 1 GiB
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found *Finding
	for i := range result.Findings {
		if result.Findings[i].ID == FindingECRUntaggedImageSprawl {
			found = &result.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("expected ECR_UNTAGGED_IMAGE_SPRAWL finding for 25 untagged images (default threshold 20)")
	}
	if found.Metadata["untagged_image_count"] != 25 {
		t.Fatalf("expected untagged_image_count=25, got %v", found.Metadata["untagged_image_count"])
	}
	if found.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate for 25 GiB of untagged images")
	}
}

func TestECRScanner_UntaggedImagesAtThreshold_NotFlagged(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{{RepositoryName: awssdk.String("ok-repo")}},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"ok-repo": untaggedImagesOfSize(20, 1024*1024*1024), // exactly the default threshold
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if f.ID == FindingECRUntaggedImageSprawl {
			t.Fatal("expected no sprawl finding when untagged count equals (not exceeds) the threshold")
		}
	}
}

func TestECRScanner_CustomThreshold(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{{RepositoryName: awssdk.String("custom-repo")}},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"custom-repo": untaggedImagesOfSize(6, 100*1024*1024),
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{ECRUntaggedThreshold: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.ID == FindingECRUntaggedImageSprawl {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sprawl finding with a custom threshold of 5 and 6 untagged images")
	}
}

func TestECRScanner_ExcludedByResourceID(t *testing.T) {
	mock := &mockECRClient{
		repos:                  []ecrtypes.Repository{{RepositoryName: awssdk.String("excluded-repo")}},
		lifecyclePolicyMissing: map[string]bool{"excluded-repo": true},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	cfg := ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"excluded-repo": true}}}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded repository, got %d", len(result.Findings))
	}
}

func TestECRScanner_TagExcludeHasNoEffect(t *testing.T) {
	// WO-225: ECR repository tags require a separate ecr:ListTagsForResource
	// call this scanner doesn't make (documented known limitation) —
	// tag-based --exclude-tags has no effect on ECR findings, only
	// resource-ID exclusion does.
	mock := &mockECRClient{
		repos:                  []ecrtypes.Repository{{RepositoryName: awssdk.String("tagged-repo")}},
		lifecyclePolicyMissing: map[string]bool{"tagged-repo": true},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	cfg := ScanConfig{Exclude: ExcludeConfig{Tags: map[string]string{"Team": "payments"}}}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected the finding to still surface — tag-based exclusion is not supported for ECR repositories")
	}
}

func TestECRScanner_PaginatesRepositories(t *testing.T) {
	mock := &mockECRClient{
		repoPages: [][]ecrtypes.Repository{
			{{RepositoryName: awssdk.String("page1-repo")}},
			{{RepositoryName: awssdk.String("page2-repo")}},
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.describeReposCalls != 2 {
		t.Fatalf("expected 2 DescribeRepositories calls across pages, got %d", mock.describeReposCalls)
	}
	if result.ResourcesScanned != 2 {
		t.Fatalf("expected 2 repositories scanned across both pages, got %d", result.ResourcesScanned)
	}
}

func TestECRScanner_PaginatesImages(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{{RepositoryName: awssdk.String("paged-repo")}},
		untaggedImagePages: map[string][][]ecrtypes.ImageDetail{
			"paged-repo": {
				untaggedImagesOfSize(15, 1024*1024*1024),
				untaggedImagesOfSize(10, 1024*1024*1024),
			},
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.describeImagesCalls["paged-repo"] != 2 {
		t.Fatalf("expected 2 DescribeImages calls across pages, got %d", mock.describeImagesCalls["paged-repo"])
	}

	var found *Finding
	for i := range result.Findings {
		if result.Findings[i].ID == FindingECRUntaggedImageSprawl {
			found = &result.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("expected sprawl finding summing untagged images across both pages")
	}
	if found.Metadata["untagged_image_count"] != 25 {
		t.Fatalf("expected untagged_image_count=25 (15+10 across pages), got %v", found.Metadata["untagged_image_count"])
	}
}

func TestECRScanner_LifecyclePolicyGenericError_SkipsFindingButContinuesImageCheck(t *testing.T) {
	mock := &mockECRClient{
		repos:              []ecrtypes.Repository{{RepositoryName: awssdk.String("flaky-repo")}},
		lifecyclePolicyErr: map[string]error{"flaky-repo": errors.New("throttled")},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"flaky-repo": untaggedImagesOfSize(25, 1024*1024*1024),
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if f.ID == FindingECRNoLifecyclePolicy {
			t.Fatal("expected no ECR_NO_LIFECYCLE_POLICY finding when the policy check itself failed with a generic error")
		}
	}
	found := false
	for _, f := range result.Findings {
		if f.ID == FindingECRUntaggedImageSprawl {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the untagged-image check to still run even though the lifecycle policy check failed")
	}
}

func TestECRScanner_DescribeImagesError_SkipsRepoImageCheckOnly(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{
			{RepositoryName: awssdk.String("broken-repo")},
			{RepositoryName: awssdk.String("fine-repo")},
		},
		lifecyclePolicyMissing: map[string]bool{"broken-repo": true, "fine-repo": true},
		describeImagesErr:      map[string]error{"broken-repo": errors.New("throttled")},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, f := range result.Findings {
		if f.ID == FindingECRNoLifecyclePolicy {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 ECR_NO_LIFECYCLE_POLICY findings despite one repo's image check failing, got %d", count)
	}
}

func TestECRScanner_BothFindingsForSameRepository(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{
			{RepositoryName: awssdk.String("neglected-repo"), RepositoryArn: awssdk.String("arn:aws:ecr:us-east-1:123456789012:repository/neglected-repo")},
		},
		lifecyclePolicyMissing: map[string]bool{"neglected-repo": true},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"neglected-repo": untaggedImagesOfSize(30, 1024*1024*1024),
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected both findings for a repo with no policy AND untagged sprawl, got %d", len(result.Findings))
	}

	var sawNoPolicy, sawSprawl bool
	for _, f := range result.Findings {
		if f.ResourceID != "neglected-repo" {
			t.Fatalf("expected both findings to reference neglected-repo, got %s", f.ResourceID)
		}
		switch f.ID {
		case FindingECRNoLifecyclePolicy:
			sawNoPolicy = true
		case FindingECRUntaggedImageSprawl:
			sawSprawl = true
		}
	}
	if !sawNoPolicy || !sawSprawl {
		t.Fatalf("expected both ECR_NO_LIFECYCLE_POLICY and ECR_UNTAGGED_IMAGE_SPRAWL, got no_policy=%v sprawl=%v", sawNoPolicy, sawSprawl)
	}
}

func TestECRScanner_FindingsDefaultToDirectRemediation(t *testing.T) {
	mock := &mockECRClient{
		repos: []ecrtypes.Repository{
			{RepositoryName: awssdk.String("plain-repo")},
		},
		lifecyclePolicyMissing: map[string]bool{"plain-repo": true},
		untaggedImages: map[string][]ecrtypes.ImageDetail{
			"plain-repo": untaggedImagesOfSize(25, 1024*1024*1024),
		},
	}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.EffectiveRemediationPath() != RemediationDirect {
			t.Fatalf("expected %s to default to RemediationDirect, got %s", f.ID, f.EffectiveRemediationPath())
		}
	}
}

func TestECRScanner_NoRepositories(t *testing.T) {
	mock := &mockECRClient{repos: nil}
	scanner := NewECRScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestECRScanner_Type(t *testing.T) {
	scanner := &ECRScanner{}
	if scanner.Type() != ResourceECR {
		t.Fatalf("expected ResourceECR, got %s", scanner.Type())
	}
}
