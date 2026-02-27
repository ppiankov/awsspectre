package pricing

import (
	"encoding/json"
	"log/slog"
)

const hoursPerMonth = 730

// pricingDB holds the parsed pricing data keyed by resource type, then instance/volume type, then region.
var pricingDB map[string]map[string]map[string]float64

func init() {
	if err := json.Unmarshal(pricingData, &pricingDB); err != nil {
		slog.Warn("Failed to parse embedded pricing data", "error", err)
		pricingDB = make(map[string]map[string]map[string]float64)
	}
}

// lookupHourly returns the hourly on-demand price for a resource type, instance type, and region.
// Returns 0 and false if not found.
func lookupHourly(resourceType, instanceType, region string) (float64, bool) {
	types, ok := pricingDB[resourceType]
	if !ok {
		return 0, false
	}
	regions, ok := types[instanceType]
	if !ok {
		return 0, false
	}
	price, ok := regions[region]
	if !ok {
		// Fall back to us-east-1 as default
		price, ok = regions["us-east-1"]
		if !ok {
			return 0, false
		}
	}
	return price, true
}

// lookupMonthly returns the monthly flat rate for a resource type and region.
// Used for EIP, NAT Gateway, ALB, NLB which have monthly fixed costs.
func lookupMonthly(resourceType, region string) (float64, bool) {
	types, ok := pricingDB[resourceType]
	if !ok {
		return 0, false
	}
	regions, ok := types["default"]
	if !ok {
		return 0, false
	}
	price, ok := regions[region]
	if !ok {
		price, ok = regions["us-east-1"]
		if !ok {
			return 0, false
		}
	}
	return price, true
}

// MonthlyEC2Cost returns the estimated monthly cost for an EC2 instance type in a region.
// Returns 0 if the instance type is not in the pricing database.
func MonthlyEC2Cost(instanceType, region string) float64 {
	hourly, ok := lookupHourly("ec2", instanceType, region)
	if !ok {
		return 0
	}
	return hourly * hoursPerMonth
}

// MonthlyEBSCost returns the estimated monthly cost for an EBS volume.
// Price is per GiB per month.
func MonthlyEBSCost(volumeType string, sizeGiB int, region string) float64 {
	perGiB, ok := lookupHourly("ebs", volumeType, region)
	if !ok {
		return 0
	}
	return perGiB * float64(sizeGiB)
}

// MonthlyEIPCost returns the monthly cost of an unassociated Elastic IP.
func MonthlyEIPCost(region string) float64 {
	cost, _ := lookupMonthly("eip", region)
	return cost
}

// MonthlyNATGatewayCost returns the base monthly cost of a NAT Gateway (excluding data transfer).
func MonthlyNATGatewayCost(region string) float64 {
	cost, _ := lookupMonthly("nat_gateway", region)
	return cost
}

// MonthlyALBCost returns the base monthly cost of an ALB (excluding LCU charges).
func MonthlyALBCost(region string) float64 {
	cost, _ := lookupMonthly("alb", region)
	return cost
}

// MonthlyNLBCost returns the base monthly cost of an NLB (excluding LCU charges).
func MonthlyNLBCost(region string) float64 {
	cost, _ := lookupMonthly("nlb", region)
	return cost
}

// MonthlyRDSCost returns the estimated monthly cost for an RDS instance.
// If multiAZ is true, the cost is doubled.
func MonthlyRDSCost(instanceClass, region string, multiAZ bool) float64 {
	hourly, ok := lookupHourly("rds", instanceClass, region)
	if !ok {
		return 0
	}
	cost := hourly * hoursPerMonth
	if multiAZ {
		cost *= 2
	}
	return cost
}

// rdsMemoryGiB maps RDS instance classes to total memory in GiB.
var rdsMemoryGiB = map[string]int64{
	"db.t3.micro":   1,
	"db.t3.small":   2,
	"db.t3.medium":  4,
	"db.t3.large":   8,
	"db.m5.large":   8,
	"db.m5.xlarge":  16,
	"db.m5.2xlarge": 32,
	"db.r5.large":   16,
	"db.r5.xlarge":  32,
	"db.r5.2xlarge": 64,
}

const bytesPerGiB = 1024 * 1024 * 1024

// RDSInstanceMemoryBytes returns the total memory in bytes for an RDS instance class.
// Returns (0, false) if the instance class is not in the lookup table.
func RDSInstanceMemoryBytes(instanceClass string) (int64, bool) {
	gib, ok := rdsMemoryGiB[instanceClass]
	if !ok {
		return 0, false
	}
	return gib * bytesPerGiB, true
}

// MonthlySnapshotCost returns the estimated monthly cost for a snapshot.
// Price is per GiB per month.
func MonthlySnapshotCost(sizeGiB int, region string) float64 {
	perGiB, ok := lookupHourly("snapshot", "default", region)
	if !ok {
		return 0
	}
	return perGiB * float64(sizeGiB)
}
