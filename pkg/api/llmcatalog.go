/*
 * Copyright (c) 2022 NetLOX Inc
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
	"net/http"
)

type LLMCatalogAPI struct {
	CommonAPI
}

// LLMCatalog represents an LLM catalog profile
type LLMCatalog struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Weights     LLMCatalogWeights    `json:"weights"`
	Thresholds  LLMCatalogThresholds `json:"thresholds"`
	IsBuiltin   bool                 `json:"is_builtin,omitempty"`
	Version     string               `json:"version,omitempty"`
}

// LLMCatalogWeights defines scoring weights for routing algorithm
type LLMCatalogWeights struct {
	QueuedRequests   int `json:"queued_requests"`
	SwappedRequests  int `json:"swapped_requests"`
	KVCacheUsagePerc int `json:"kv_cache_usage_perc"`
}

// LLMCatalogThresholds defines health status thresholds
type LLMCatalogThresholds struct {
	QueueHigh      int `json:"queue_high"`
	QueueCritical  int `json:"queue_critical"`
	SwapHigh       int `json:"swap_high"`
	SwapCritical   int `json:"swap_critical"`
	CacheHigh      int `json:"cache_high"`
	CacheCritical  int `json:"cache_critical"`
}

// GetAll retrieves all available LLM catalog profiles
func (l *LLMCatalogAPI) GetAll(ctx context.Context) (*http.Response, error) {
	getURL := l.GetUrlString()
	return l.restClient.GET(ctx, getURL)
}

// Get retrieves a specific LLM catalog profile by name
func (l *LLMCatalogAPI) Get(ctx context.Context, catalogName string) (*http.Response, error) {
	return l.SubResources([]string{catalogName}).Get(ctx)
}
