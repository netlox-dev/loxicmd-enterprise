/*
 * Copyright (c) 2024-2025 LoxiLB Authors
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

const loxiL4TraceResource = "config/l4trace"

// L4Trace represents the L4 connection tracing API client
type L4Trace struct {
	CommonAPI
}

// EnableCreate sends a POST request to enable L4 tracing with sampling configuration
func (t *L4Trace) EnableCreate(ctx context.Context, body interface{}) (*RESTResponse, error) {
	t.requestInfo.subResource = []string{"enable"}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	postURL := t.GetUrlString()
	resp, err := t.restClient.POST(ctx, postURL, jsonBody)
	if err != nil {
		return nil, err
	}

	return &RESTResponse{
		StatusCode: resp.StatusCode,
		Result:     nil,
	}, nil
}

// Delete sends a POST request to disable L4 tracing
func (t *L4Trace) Delete(ctx context.Context) (*RESTResponse, error) {
	t.requestInfo.subResource = []string{"disable"}

	postURL := t.GetUrlString()
	resp, err := t.restClient.POST(ctx, postURL, nil)
	if err != nil {
		return nil, err
	}

	return &RESTResponse{
		StatusCode: resp.StatusCode,
		Result:     nil,
	}, nil
}

// Get sends a GET request to retrieve L4 tracing status
func (t *L4Trace) Get(ctx context.Context) (*RESTResponse, error) {
	t.requestInfo.subResource = []string{"status"}

	getURL := t.GetUrlString()
	resp, err := t.restClient.GET(ctx, getURL)
	if err != nil {
		return nil, err
	}

	// Parse response body
	var status L4TraceStatusResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return nil, err
		}
	}

	return &RESTResponse{
		StatusCode: resp.StatusCode,
		Result:     status,
	}, nil
}

// SetSampling sends a PUT request to update sampling rate
func (t *L4Trace) SetSampling(ctx context.Context, body interface{}) (*RESTResponse, error) {
	t.requestInfo.subResource = []string{"sampling"}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	putURL := t.GetUrlString()
	resp, err := t.restClient.PUT(ctx, putURL, jsonBody)
	if err != nil {
		return nil, err
	}

	return &RESTResponse{
		StatusCode: resp.StatusCode,
		Result:     nil,
	}, nil
}

// ResetStats sends a POST request to reset L4 tracing statistics
func (t *L4Trace) ResetStats(ctx context.Context) (*RESTResponse, error) {
	t.requestInfo.subResource = []string{"stats", "reset"}

	postURL := t.GetUrlString()
	resp, err := t.restClient.POST(ctx, postURL, nil)
	if err != nil {
		return nil, err
	}

	return &RESTResponse{
		StatusCode: resp.StatusCode,
		Result:     nil,
	}, nil
}

// L4TraceStatusResponse represents the response for /config/l4trace/status
type L4TraceStatusResponse struct {
	Enabled       bool         `json:"enabled"`
	SamplingRate  int64        `json:"sampling_rate"`
	ConfigVersion int64        `json:"config_version"`
	Stats         L4TraceStats `json:"stats"`
}

// L4TraceStats represents the statistics for L4 connection tracing
type L4TraceStats struct {
	TotalEvents     int64 `json:"total_events"`
	SampledEvents   int64 `json:"sampled_events"`
	DroppedEvents   int64 `json:"dropped_events"`
	TCPEvents       int64 `json:"tcp_events"`
	SctpEvents      int64 `json:"sctp_events"`
	ConnNew         int64 `json:"conn_new"`
	ConnEstablished int64 `json:"conn_established"`
	ConnClosed      int64 `json:"conn_closed"`
	ConnTimeout     int64 `json:"conn_timeout"`
	ConnReset       int64 `json:"conn_reset"`
	ConnError       int64 `json:"conn_error"`
}

// RESTResponse wraps the HTTP response for easier handling
type RESTResponse struct {
	StatusCode int
	Result     interface{}
}
