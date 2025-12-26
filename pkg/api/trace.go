/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package api

import (
	"context"
	"encoding/json"
	"net/http"
)

// Trace represents the HTTP/HTTPS tracing API client
type Trace struct {
	CommonAPI
}

// Post sends a POST request to trace endpoints (enable/disable/otlp)
func (t *Trace) Post(ctx context.Context, endpoint string, body interface{}) (*http.Response, error) {
	t.requestInfo.subResource = []string{endpoint}
	
	if body == nil {
		// For enable/disable endpoints
		postURL := t.GetUrlString()
		return t.restClient.POST(ctx, postURL, nil)
	}
	
	// For OTLP configuration
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	postURL := t.GetUrlString()
	return t.restClient.POST(ctx, postURL, jsonBody)
}

// Get sends a GET request to trace endpoints
func (t *Trace) Get(ctx context.Context, endpoint string, subpath string) (*http.Response, error) {
	if subpath != "" {
		t.requestInfo.subResource = []string{endpoint, subpath}
	} else {
		t.requestInfo.subResource = []string{endpoint}
	}
	getURL := t.GetUrlString()
	return t.restClient.GET(ctx, getURL)
}

// Delete sends a DELETE request to trace endpoints
func (t *Trace) Delete(ctx context.Context, endpoint string, subpath string) (*http.Response, error) {
	if subpath != "" {
		t.requestInfo.subResource = []string{endpoint, subpath}
	} else {
		t.requestInfo.subResource = []string{endpoint}
	}
	deleteURL := t.GetUrlString()
	return t.restClient.DELETE(ctx, deleteURL)
}

// Put sends a PUT request to update catalog parser mapping
func (t *Trace) Put(ctx context.Context, catalogID int, body interface{}) (*http.Response, error) {
	t.requestInfo.subResource = []string{"catalog", string(rune(catalogID)), "parser"}
	
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	putURL := t.GetUrlString()
	return t.restClient.PUT(ctx, putURL, jsonBody)
}

// TraceStatusResponse represents the response for /config/trace/status
type TraceStatusResponse struct {
	Enabled         bool    `json:"enabled"`
	TotalEvents     int64   `json:"total_events"`
	DroppedEvents   int64   `json:"dropped_events"`
	RingUtilization []int32 `json:"ring_utilization"`
	OTLPEndpoint    string  `json:"otlp_endpoint"`
	OTLPProtocol    string  `json:"otlp_protocol"`
	OTLPConnected   bool    `json:"otlp_connected"`
}

// OTLPConfigRequest represents the request for configuring OTLP endpoint
type OTLPConfigRequest struct {
	Endpoint      string            `json:"endpoint"`
	Protocol      string            `json:"protocol"`
	UseTLS        bool              `json:"use_tls"`
	TLSSkipVerify bool              `json:"tls_skip_verify"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// OTLPConfigResponse represents the response for /config/trace/otlp GET
type OTLPConfigResponse struct {
	Endpoint      string            `json:"endpoint"`
	Protocol      string            `json:"protocol"`
	UseTLS        bool              `json:"use_tls"`
	TLSSkipVerify bool              `json:"tls_skip_verify"`
	Headers       map[string]string `json:"headers,omitempty"`
	Connected     bool              `json:"connected"`
}

// TraceCatalogEntry represents a single tracing catalog
type TraceCatalogEntry struct {
	CatalogID   int    `json:"catalog_id"`
	CatalogName string `json:"catalog_name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Enabled     bool   `json:"enabled"`
	SampleRate  int    `json:"sample_rate"`
	ParserType  string `json:"parser_type"`
}

// TraceCatalogsResponse represents the response for /config/trace/catalogs
type TraceCatalogsResponse struct {
	Catalogs []TraceCatalogEntry `json:"catalogs"`
}

// TraceParserInfo represents information about a trace parser
type TraceParserInfo struct {
	Name           string   `json:"name"`
	Protocol       string   `json:"protocol"`
	Version        string   `json:"version"`
	SupportedPaths []string `json:"supported_paths"`
	Capabilities   []string `json:"capabilities"`
}

// TraceParsersResponse represents the response for /config/trace/parsers
type TraceParsersResponse struct {
	Parsers []TraceParserInfo `json:"parsers"`
}

// CatalogParserMapping represents the parser assignment for a catalog
type CatalogParserMapping struct {
	CatalogID   int    `json:"catalog_id"`
	CatalogName string `json:"catalog_name"`
	ParserName  string `json:"parser_name"`
	ParserType  string `json:"parser_type"`
}

// TraceParserUpdate represents the request to update a catalog's parser
type TraceParserUpdate struct {
	ParserName string `json:"parser_name"`
}
