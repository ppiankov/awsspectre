package report

import (
	"encoding/json"
	"fmt"
)

// jsonEnvelope wraps Data with a schema field for spectre/v1 output.
type jsonEnvelope struct {
	Schema string `json:"$schema"`
	Data
}

// Generate writes spectre/v1 JSON envelope output.
func (r *JSONReporter) Generate(data Data) error {
	envelope := jsonEnvelope{
		Schema: "spectre/v1",
		Data:   data,
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}
