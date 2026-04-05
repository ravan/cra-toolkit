// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit

import (
	"encoding/json"
	"fmt"
	"io"
)

// Provenance holds parsed SLSA provenance metadata.
type Provenance struct {
	Exists     bool   `json:"exists"`
	BuilderID  string `json:"builder_id,omitempty"`
	SourceRepo string `json:"source_repo,omitempty"`
	BuildType  string `json:"build_type,omitempty"`
}

// slsaStatement is the in-toto statement envelope used by both SLSA v0.2 and v1.0.
type slsaStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// slsaV1Predicate models the SLSA v1.0 provenance predicate.
type slsaV1Predicate struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Workflow struct {
				Repository string `json:"repository"`
			} `json:"workflow"`
		} `json:"externalParameters"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

// slsaV02Predicate models the SLSA v0.2 provenance predicate.
type slsaV02Predicate struct {
	Builder struct {
		ID string `json:"id"`
	} `json:"builder"`
	Invocation struct {
		ConfigSource struct {
			URI string `json:"uri"`
		} `json:"configSource"`
	} `json:"invocation"`
}

// ParseProvenance parses an SLSA provenance document (v0.2 or v1.0) from the given reader.
func ParseProvenance(r io.Reader) (*Provenance, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading provenance: %w", err)
	}

	var stmt slsaStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("parsing provenance JSON: %w", err)
	}

	prov := &Provenance{
		Exists:    true,
		BuildType: stmt.PredicateType,
	}

	switch {
	case stmt.PredicateType == "https://slsa.dev/provenance/v1":
		var pred slsaV1Predicate
		if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
			return nil, fmt.Errorf("parsing SLSA v1 predicate: %w", err)
		}
		prov.BuilderID = pred.RunDetails.Builder.ID
		prov.SourceRepo = pred.BuildDefinition.ExternalParameters.Workflow.Repository

	case stmt.PredicateType == "https://slsa.dev/provenance/v0.2":
		var pred slsaV02Predicate
		if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
			return nil, fmt.Errorf("parsing SLSA v0.2 predicate: %w", err)
		}
		prov.BuilderID = pred.Builder.ID
		prov.SourceRepo = pred.Invocation.ConfigSource.URI

	default:
		// Unknown predicate type — still mark as existing with whatever we have.
	}

	return prov, nil
}
