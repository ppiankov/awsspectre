package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Generate writes human-readable terminal output.
func (r *TextReporter) Generate(data Data) error {
	tw := tabwriter.NewWriter(r.Writer, 0, 4, 2, ' ', 0)
	w := &errWriter{w: r.Writer}

	w.println("awsspectre — AWS Resource Waste Report")
	w.println(strings.Repeat("=", 40))
	w.println("")

	if len(data.Findings) == 0 {
		w.println("No idle resources found.")
		w.println("")
		writeTextSummary(w, data)
		return w.err
	}

	w.printf("Found %d idle resources with estimated monthly waste of $%.2f\n\n",
		data.Summary.TotalFindings, data.Summary.TotalMonthlyWaste)

	tw2 := &errWriter{w: tw}
	tw2.printf("SEVERITY\tTYPE\tRESOURCE\tREGION\tWASTE/MO\tMESSAGE\n")
	tw2.printf("--------\t----\t--------\t------\t--------\t-------\n")

	for _, f := range data.Findings {
		name := f.ResourceID
		if f.ResourceName != "" {
			name = f.ResourceName
		}
		tw2.printf("%s\t%s\t%s\t%s\t$%.2f\t%s\n",
			f.Severity, f.ResourceType, name, f.Region, f.EstimatedMonthlyWaste, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	w.println("")
	writeTextSummary(w, data)
	return w.err
}

func writeTextSummary(w *errWriter, data Data) {
	w.println("Summary")
	w.println("-------")
	w.printf("Resources scanned:       %d\n", data.Summary.TotalResourcesScanned)
	w.printf("Regions scanned:         %d\n", data.Summary.RegionsScanned)
	w.printf("Total findings:          %d\n", data.Summary.TotalFindings)
	w.printf("Estimated monthly waste: $%.2f\n", data.Summary.TotalMonthlyWaste)

	if len(data.Summary.BySeverity) > 0 {
		parts := formatMapSorted(data.Summary.BySeverity)
		w.printf("By severity:             %s\n", strings.Join(parts, ", "))
	}
	if len(data.Summary.ByResourceType) > 0 {
		parts := formatMapSorted(data.Summary.ByResourceType)
		w.printf("By resource type:        %s\n", strings.Join(parts, ", "))
	}

	if len(data.Errors) > 0 {
		w.printf("\nWarnings (%d):\n", len(data.Errors))
		for _, e := range data.Errors {
			w.printf("  - %s\n", e)
		}
	}
}

// errWriter wraps an io.Writer and captures the first error.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(s string) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, s)
}

func formatMapSorted(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return parts
}
