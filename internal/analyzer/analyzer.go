package analyzer

import (
	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

// Analyze filters findings by minimum cost and computes aggregated summary statistics.
func Analyze(result *awstype.ScanResult, cfg AnalyzerConfig) *AnalysisResult {
	var filtered []awstype.Finding
	for _, f := range result.Findings {
		if includeFinding(f, cfg.MinMonthlyCost) {
			filtered = append(filtered, f)
		}
	}

	summary := Summary{
		TotalResourcesScanned: result.ResourcesScanned,
		TotalFindings:         len(filtered),
		RegionsScanned:        result.RegionsScanned,
		BySeverity:            make(map[string]int),
		ByResourceType:        make(map[string]int),
	}

	for _, f := range filtered {
		summary.TotalMonthlyWaste += f.EstimatedMonthlyWaste
		summary.BySeverity[string(f.Severity)]++
		summary.ByResourceType[string(f.ResourceType)]++
	}

	return &AnalysisResult{
		Findings: filtered,
		Summary:  summary,
		Errors:   result.Errors,
	}
}

func includeFinding(f awstype.Finding, minMonthlyCost float64) bool {
	if f.EstimatedMonthlyWaste >= minMonthlyCost {
		return true
	}

	// WO-190: CloudFront hygiene findings intentionally carry no direct monthly waste.
	switch f.ID {
	case awstype.FindingCloudFrontDisabled, awstype.FindingCloudFrontIdle:
		return true
	default:
		return false
	}
}
