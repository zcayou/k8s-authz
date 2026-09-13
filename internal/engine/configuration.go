package engine

import "encoding/json"

// Configuration returns the stock OPA configuration: request bodies bounded
// by the largest state document, and console decision logs when logDecisions
// is set, which system.log masks and limits to endpoint decisions.
func Configuration(logDecisions bool) ([]byte, error) {
	configuration := map[string]any{
		"server": map[string]any{"decoding": map[string]int64{"max_length": MaxContentBytes}},
	}
	if logDecisions {
		configuration["decision_logs"] = map[string]any{"console": true}
	}
	return json.Marshal(configuration)
}
