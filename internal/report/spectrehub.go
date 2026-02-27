package report

import (
	"encoding/json"
	"fmt"
)

// spectreHubEnvelope wraps Data for SpectreHub ingestion.
type spectreHubEnvelope struct {
	Schema string `json:"schema"`
	Data
}

// Generate writes SpectreHub envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	envelope := spectreHubEnvelope{
		Schema: "spectre/v1",
		Data:   data,
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encode SpectreHub report: %w", err)
	}
	return nil
}
