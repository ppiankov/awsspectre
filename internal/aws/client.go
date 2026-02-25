package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Client wraps the AWS SDK configuration for creating service clients.
type Client struct {
	cfg aws.Config
}

// NewClient creates a new AWS client using the specified profile and region.
// If profile is empty, the default credential chain is used.
// If region is empty, the default region from config/env is used.
func NewClient(ctx context.Context, profile, region string) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error

	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &Client{cfg: cfg}, nil
}

// Config returns the underlying AWS config.
func (c *Client) Config() aws.Config {
	return c.cfg
}

// ConfigForRegion returns a copy of the AWS config with the region overridden.
func (c *Client) ConfigForRegion(region string) aws.Config {
	cfg := c.cfg.Copy()
	cfg.Region = region
	return cfg
}

// ListEnabledRegions returns all enabled regions for the account.
func (c *Client) ListEnabledRegions(ctx context.Context) ([]string, error) {
	svc := ec2.NewFromConfig(c.cfg)
	out, err := svc.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}

	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}

	slog.Debug("Discovered enabled regions", "count", len(regions))
	return regions, nil
}
