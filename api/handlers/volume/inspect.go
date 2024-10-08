// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package volume

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/runfinch/finch-daemon/api/response"
	"github.com/runfinch/finch-daemon/pkg/errdefs"
)

// inspect function returns the details of a volume if exists or else return not found error.
func (h *handler) inspect(w http.ResponseWriter, r *http.Request) {
	vol := mux.Vars(r)["name"]
	resp, err := h.service.Inspect(vol)
	if err != nil {
		code := http.StatusInternalServerError
		if errdefs.IsNotFound(err) {
			code = http.StatusNotFound
		}
		response.JSON(w, code, response.NewError(err))
		return
	}
	response.JSON(w, http.StatusOK, resp)
}
