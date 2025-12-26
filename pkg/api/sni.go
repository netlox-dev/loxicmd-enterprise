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
	"net/http"
)

type SNICertificate struct {
	CommonAPI
}

type SNICertificateGetResponse struct {
	SniAttr []SNICertificateEntry `json:"sniAttr"`
}

type SNICertificateEntry struct {
	Hostname *string `json:"hostname"`
	CertPath string  `json:"certPath,omitempty"`
}

// Get retrieves all global SNI certificates
func (s *SNICertificate) Get(ctx context.Context) (*http.Response, error) {
	return s.CommonAPI.Get(ctx)
}

// Create registers a new SNI certificate
func (s *SNICertificate) Create(ctx context.Context, model SNICertificateEntry) (*http.Response, error) {
	return s.CommonAPI.Create(ctx, model)
}

// Delete unregisters an SNI certificate
func (s *SNICertificate) Delete(ctx context.Context, model SNICertificateEntry) (*http.Response, error) {
	return s.CommonAPI.DeleteWithBody(ctx, model)
}
