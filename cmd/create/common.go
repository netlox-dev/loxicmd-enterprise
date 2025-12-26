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

package create

import (
	"encoding/json"
	"fmt"
	"loxicmd/pkg/api"
)

type CreateResult struct {
	Result string `json:"result"`
}

func PrintCreateResult(resp *http.Response, o api.RESTOptions) {
	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(resp, "", "\t")
		fmt.Println(string(resultIndent))
		return
	}
	fmt.Println("L4 tracing enabled successfully")
}
