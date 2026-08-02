package pricing

import "testing"

func TestMonthlyEC2Cost(t *testing.T) {
	tests := []struct {
		name         string
		instanceType string
		region       string
		wantNonZero  bool
	}{
		{"t3.large us-east-1", "t3.large", "us-east-1", true},
		{"m5.xlarge eu-west-1", "m5.xlarge", "eu-west-1", true},
		{"unknown type", "x99.mega", "us-east-1", false},
		{"known type unknown region falls back to us-east-1", "t3.micro", "af-south-1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := MonthlyEC2Cost(tt.instanceType, tt.region)
			if tt.wantNonZero && cost == 0 {
				t.Fatalf("expected non-zero cost for %s in %s", tt.instanceType, tt.region)
			}
			if !tt.wantNonZero && cost != 0 {
				t.Fatalf("expected zero cost for %s in %s, got %f", tt.instanceType, tt.region, cost)
			}
		})
	}
}

func TestMonthlyEC2Cost_GPUInstanceTypes(t *testing.T) {
	// WO-238: GPU-family instance types previously had no pricing.json entries
	// at all, so an idle GPU instance (WO-235) would report $0 estimated
	// waste for the account's most expensive compute.
	gpuTypes := []string{
		"g3.4xlarge", "g4dn.xlarge", "g5.xlarge", "g6.xlarge",
		"p2.xlarge", "p3.2xlarge", "p4d.24xlarge", "p5.48xlarge",
		"inf1.xlarge", "inf2.xlarge", "trn1.2xlarge",
	}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}

	for _, instanceType := range gpuTypes {
		for _, region := range regions {
			cost := MonthlyEC2Cost(instanceType, region)
			if cost == 0 {
				t.Errorf("expected non-zero cost for %s in %s, got $0", instanceType, region)
			}
		}
	}
}

func TestMonthlyEC2Cost_Calculation(t *testing.T) {
	// t3.large in us-east-1 is $0.0832/hr * 730 hrs = ~$60.74
	cost := MonthlyEC2Cost("t3.large", "us-east-1")
	if cost < 60 || cost > 62 {
		t.Fatalf("expected ~$60.74, got $%.2f", cost)
	}
}

func TestMonthlyEBSCost(t *testing.T) {
	// gp3 in us-east-1 is $0.08/GiB/month
	cost := MonthlyEBSCost("gp3", 100, "us-east-1")
	if cost != 8.0 {
		t.Fatalf("expected $8.00, got $%.2f", cost)
	}
}

func TestMonthlyEBSCost_UnknownType(t *testing.T) {
	cost := MonthlyEBSCost("unknown", 100, "us-east-1")
	if cost != 0 {
		t.Fatalf("expected $0, got $%.2f", cost)
	}
}

// TestGP3CheaperThanGP2_AllScannedRegions verifies the assumption behind
// GP2_MIGRATION_CANDIDATE (WO-222): that gp3 is cheaper than gp2 per GiB, in
// every one of the 17 regions this tool actually scans (all AWS regions with
// OptInStatus opt-in-not-required or opted-in as of this WO's live account
// check) — not just the 4 regions previously hardcoded. Exact rates are
// asserted, not just the gp3<gp2 relation, because lookupHourly's us-east-1
// fallback (pricing.go) would ALSO satisfy gp3<gp2 for any region missing
// from pricing.json — a relation-only check can't distinguish "real
// per-region data present" from "silently fell back to us-east-1." Rates
// below are pulled from the AWS Price List API (aws pricing get-products,
// publicationDate 2026-07-28) — WO-233. No inversion was found anywhere;
// this test is the regression guard for that finding, not a fix for one.
func TestGP3CheaperThanGP2_AllScannedRegions(t *testing.T) {
	// Regions whose real rate differs from the us-east-1 fallback (0.10/0.08)
	// prove the lookup isn't silently falling back — us-east-1/us-east-2/
	// us-west-2 genuinely share us-east-1's rate, so they're excluded from
	// this specific proof but still covered by the gp3<gp2 loop below.
	wantRates := map[string]struct{ gp2, gp3 float64 }{
		"us-west-1":      {0.12, 0.096},
		"ca-central-1":   {0.11, 0.088},
		"sa-east-1":      {0.19, 0.152},
		"eu-west-1":      {0.11, 0.088},
		"eu-west-2":      {0.116, 0.0928},
		"eu-west-3":      {0.116, 0.0928},
		"eu-central-1":   {0.119, 0.0952},
		"eu-north-1":     {0.1045, 0.0836},
		"ap-south-1":     {0.114, 0.0912},
		"ap-southeast-1": {0.12, 0.096},
		"ap-southeast-2": {0.12, 0.096},
		"ap-northeast-1": {0.12, 0.096},
		"ap-northeast-2": {0.114, 0.0912},
		"ap-northeast-3": {0.12, 0.096},
	}
	for region, want := range wantRates {
		gp2, _ := lookupHourly("ebs", "gp2", region)
		if gp2 != want.gp2 {
			t.Errorf("%s: gp2 = $%.4f, want $%.4f (real per-region data, not the us-east-1 fallback of $0.10)", region, gp2, want.gp2)
		}
		gp3, _ := lookupHourly("ebs", "gp3", region)
		if gp3 != want.gp3 {
			t.Errorf("%s: gp3 = $%.4f, want $%.4f (real per-region data, not the us-east-1 fallback of $0.08)", region, gp3, want.gp3)
		}
	}

	scannedRegions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"ca-central-1", "sa-east-1",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
		"ap-south-1", "ap-southeast-1", "ap-southeast-2",
		"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	}
	for _, region := range scannedRegions {
		gp2, ok := lookupHourly("ebs", "gp2", region)
		if !ok {
			t.Fatalf("%s: no gp2 pricing entry", region)
		}
		gp3, ok := lookupHourly("ebs", "gp3", region)
		if !ok {
			t.Fatalf("%s: no gp3 pricing entry", region)
		}
		if gp3 >= gp2 {
			t.Errorf("%s: gp3 ($%.4f) is not cheaper than gp2 ($%.4f) — GP2_MIGRATION_CANDIDATE's assumption is violated here", region, gp3, gp2)
		}
	}
}

func TestMonthlyEIPCost(t *testing.T) {
	cost := MonthlyEIPCost("us-east-1")
	if cost == 0 {
		t.Fatal("expected non-zero EIP cost")
	}
}

func TestMonthlyNATGatewayCost(t *testing.T) {
	cost := MonthlyNATGatewayCost("us-east-1")
	if cost == 0 {
		t.Fatal("expected non-zero NAT Gateway cost")
	}
}

func TestNATGatewayDataCostPerGB(t *testing.T) {
	cost := NATGatewayDataCostPerGB("us-east-1")
	if cost != 0.045 {
		t.Fatalf("expected $0.045/GB, got $%f", cost)
	}
}

func TestNATGatewayDataCostPerGB_UnknownRegion(t *testing.T) {
	cost := NATGatewayDataCostPerGB("af-south-1")
	if cost != 0.045 {
		t.Fatalf("expected fallback to us-east-1 ($0.045), got $%f", cost)
	}
}

func TestMonthlyALBCost(t *testing.T) {
	cost := MonthlyALBCost("us-east-1")
	if cost == 0 {
		t.Fatal("expected non-zero ALB cost")
	}
}

func TestMonthlyNLBCost(t *testing.T) {
	cost := MonthlyNLBCost("us-east-1")
	if cost == 0 {
		t.Fatal("expected non-zero NLB cost")
	}
}

func TestMonthlyRDSCost(t *testing.T) {
	cost := MonthlyRDSCost("db.t3.medium", "us-east-1", false)
	if cost == 0 {
		t.Fatal("expected non-zero RDS cost")
	}
}

func TestMonthlyRDSCost_MultiAZ(t *testing.T) {
	single := MonthlyRDSCost("db.t3.medium", "us-east-1", false)
	multi := MonthlyRDSCost("db.t3.medium", "us-east-1", true)
	if multi != single*2 {
		t.Fatalf("expected multi-AZ to be 2x single, got single=%f multi=%f", single, multi)
	}
}

func TestMonthlySnapshotCost(t *testing.T) {
	// 100 GiB at $0.05/GiB = $5.00
	cost := MonthlySnapshotCost(100, "us-east-1")
	if cost != 5.0 {
		t.Fatalf("expected $5.00, got $%.2f", cost)
	}
}

func TestMonthlyCloudWatchLogsStorageCost(t *testing.T) {
	// 100 GiB at $0.03/GiB = $3.00
	cost := MonthlyCloudWatchLogsStorageCost(100*1024*1024*1024, "us-east-1")
	if cost != 3.0 {
		t.Fatalf("expected $3.00, got $%.2f", cost)
	}
}

func TestMonthlyCloudWatchLogsStorageCost_Zero(t *testing.T) {
	cost := MonthlyCloudWatchLogsStorageCost(0, "us-east-1")
	if cost != 0 {
		t.Fatalf("expected $0.00, got $%.2f", cost)
	}
}

func TestMonthlyECRStorageCost(t *testing.T) {
	// 25 GiB at $0.10/GiB = $2.50
	cost := MonthlyECRStorageCost(25*1024*1024*1024, "us-east-1")
	if cost != 2.5 {
		t.Fatalf("expected $2.50, got $%.2f", cost)
	}
}

func TestMonthlyECRStorageCost_Zero(t *testing.T) {
	cost := MonthlyECRStorageCost(0, "us-east-1")
	if cost != 0 {
		t.Fatalf("expected $0.00, got $%.2f", cost)
	}
}

func TestMonthlyECRStorageCost_RegionFallback(t *testing.T) {
	// Unknown region falls back to us-east-1 pricing.
	cost := MonthlyECRStorageCost(10*1024*1024*1024, "ap-northeast-1")
	if cost != 1.0 {
		t.Fatalf("expected $1.00 (us-east-1 fallback), got $%.2f", cost)
	}
}

func TestRDSInstanceMemoryBytes_Known(t *testing.T) {
	mem, ok := RDSInstanceMemoryBytes("db.r5.large")
	if !ok {
		t.Fatal("expected db.r5.large to be in memory map")
	}
	// 16 GiB = 17179869184 bytes
	if mem != 16*1024*1024*1024 {
		t.Fatalf("expected 16 GiB in bytes, got %d", mem)
	}
}

func TestRDSInstanceMemoryBytes_Unknown(t *testing.T) {
	mem, ok := RDSInstanceMemoryBytes("db.x99.unknown")
	if ok {
		t.Fatal("expected unknown class to return false")
	}
	if mem != 0 {
		t.Fatalf("expected 0 bytes for unknown class, got %d", mem)
	}
}

func TestPricingDataLoaded(t *testing.T) {
	// Verify the embedded pricing data was parsed successfully
	if pricingDB == nil {
		t.Fatal("expected pricing DB to be initialized")
	}
	if len(pricingDB) == 0 {
		t.Fatal("expected non-empty pricing DB")
	}
}
