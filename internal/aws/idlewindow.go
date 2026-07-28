package aws

import (
	"fmt"
	"time"
)

// idleWindowDescription reports the time window an idle-metric average
// actually covers. A CloudWatch average silently reflects however little
// data exists — a resource created or restarted more recently than the
// configured lookback window has far less real history than the window
// implies, so the message must say so rather than claim full-window
// confidence — WO-236 (originated for EC2), generalized to the resource
// family in WO-249 (WO-237 surveyed which scanners the pattern applies to).
func idleWindowDescription(idleDays int, createTime *time.Time, now time.Time) (description string, sufficient bool) {
	full := fmt.Sprintf("%d days", idleDays)
	if createTime == nil {
		return full, true
	}

	age := now.Sub(*createTime)
	if age < 0 {
		// Clock skew between the AWS API's timestamp and the scanner's clock —
		// treat as no observed history rather than silently absorbing the
		// skew's magnitude into a clamped-but-otherwise-normal duration.
		age = 0
	}
	fullWindow := time.Duration(idleDays) * 24 * time.Hour
	if age >= fullWindow {
		return full, true
	}

	return fmt.Sprintf("%s (insufficient running history for a confident %d-day idle verdict)", formatDuration(age), idleDays), false
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		minutes := int(d.Minutes())
		if minutes < 1 {
			minutes = 1
		}
		return fmt.Sprintf("%d minutes", minutes)
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
