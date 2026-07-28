package aws

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrailAPI is the minimal interface for CloudTrail lookup operations.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// lookupMostRecentEventTime finds the most recent CloudTrail event named
// eventName for the given resource, checking only the single most recent page
// of ResourceName-filtered events (CloudTrail returns up to 50 per call,
// sorted most-recent-first, and LookupEvents only accepts one LookupAttribute
// per call, so EventName filtering happens client-side on that page). Used to
// replace a resource's CreateTime/LaunchTime as a proxy for a different real
// lifecycle event (e.g. DetachVolume, StopInstances) — WO-241/242/243.
// Returns ok=false if the client is nil, the lookup errors, or no matching
// event is found within that page — either because the event is older than
// the trail's retention (or the account has no trail), or because 50+ other
// events on the same resource (e.g. frequent Describe/tag calls) pushed it
// past the first page — so callers fall back to their existing
// CreateTime/LaunchTime estimate either way. This is a deliberate
// best-effort tradeoff: the fallback is never worse than today's behavior.
func lookupMostRecentEventTime(ctx context.Context, client CloudTrailAPI, resourceID, eventName string) (time.Time, bool) {
	if client == nil {
		return time.Time{}, false
	}

	resourceIDCopy := resourceID
	out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
		LookupAttributes: []cttypes.LookupAttribute{
			{AttributeKey: cttypes.LookupAttributeKeyResourceName, AttributeValue: &resourceIDCopy},
		},
	})
	if err != nil {
		slog.Warn("CloudTrail lookup failed", "resource_id", resourceID, "event_name", eventName, "error", err)
		return time.Time{}, false
	}

	for _, event := range out.Events {
		if event.EventName != nil && *event.EventName == eventName && event.EventTime != nil {
			return *event.EventTime, true
		}
	}
	return time.Time{}, false
}
