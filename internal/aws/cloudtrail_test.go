package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// mockCloudTrailClient returns a fixed set of events regardless of the
// requested resource ID, for simplicity in scanner-level tests that only care
// about a single resource's events.
type mockCloudTrailClient struct {
	events []cttypes.Event
	err    error
}

func (m *mockCloudTrailClient) LookupEvents(_ context.Context, _ *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudtrail.LookupEventsOutput{Events: m.events}, nil
}

func newMockEvent(eventName string, eventTime time.Time) cttypes.Event {
	name := eventName
	t := eventTime
	return cttypes.Event{EventName: &name, EventTime: &t}
}

func TestLookupMostRecentEventTime_NilClient(t *testing.T) {
	_, ok := lookupMostRecentEventTime(context.Background(), nil, "vol-123", "DetachVolume")
	if ok {
		t.Fatal("expected ok=false for a nil client")
	}
}

func TestLookupMostRecentEventTime_MatchFound(t *testing.T) {
	expected := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	client := &mockCloudTrailClient{
		events: []cttypes.Event{
			newMockEvent("AttachVolume", time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)),
			newMockEvent("DetachVolume", expected),
			newMockEvent("CreateVolume", time.Date(2025, 7, 9, 0, 0, 0, 0, time.UTC)),
		},
	}

	got, ok := lookupMostRecentEventTime(context.Background(), client, "vol-123", "DetachVolume")
	if !ok {
		t.Fatal("expected a match")
	}
	if !got.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

func TestLookupMostRecentEventTime_NoMatch(t *testing.T) {
	client := &mockCloudTrailClient{
		events: []cttypes.Event{
			newMockEvent("AttachVolume", time.Now()),
		},
	}

	_, ok := lookupMostRecentEventTime(context.Background(), client, "vol-123", "DetachVolume")
	if ok {
		t.Fatal("expected ok=false when no event matches the requested EventName")
	}
}

func TestLookupMostRecentEventTime_APIError(t *testing.T) {
	client := &mockCloudTrailClient{err: errors.New("simulated API error")}

	_, ok := lookupMostRecentEventTime(context.Background(), client, "vol-123", "DetachVolume")
	if ok {
		t.Fatal("expected ok=false when the API call errors")
	}
}

func TestLookupMostRecentEventTime_TakesFirstMatchOnly(t *testing.T) {
	// CloudTrail returns events most-recent-first; a resource cycling through
	// multiple DetachVolume events must resolve to the newest one, not the
	// oldest.
	newest := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	client := &mockCloudTrailClient{
		events: []cttypes.Event{
			newMockEvent("DetachVolume", newest),
			newMockEvent("DetachVolume", older),
		},
	}

	got, ok := lookupMostRecentEventTime(context.Background(), client, "vol-123", "DetachVolume")
	if !ok {
		t.Fatal("expected a match")
	}
	if !got.Equal(newest) {
		t.Fatalf("expected the first (most recent) match %v, got %v", newest, got)
	}
}
