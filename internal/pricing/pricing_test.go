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
