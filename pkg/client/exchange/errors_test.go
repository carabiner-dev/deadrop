// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package exchange

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestHandleErrorResponseClassifiesAuthFailures(t *testing.T) {
	c := &Client{}
	for _, tc := range []struct {
		name          string
		statusCode    int
		body          string
		wantAuth      bool
		wantInMessage string
	}{
		{
			name:          "invalid_token is auth required",
			statusCode:    http.StatusBadRequest,
			body:          `{"error":"invalid_token","error_description":"token is expired (exp)"}`,
			wantAuth:      true,
			wantInMessage: "invalid_token",
		},
		{
			name:       "invalid_grant is auth required",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_grant","error_description":"identity rejected"}`,
			wantAuth:   true,
		},
		{
			name:       "unparseable 401 body is auth required",
			statusCode: http.StatusUnauthorized,
			body:       `not json`,
			wantAuth:   true,
		},
		{
			name:       "invalid_request is not auth required",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_request","error_description":"missing audience"}`,
			wantAuth:   false,
		},
		{
			name:       "server error is not auth required",
			statusCode: http.StatusServiceUnavailable,
			body:       `service unavailable`,
			wantAuth:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.handleErrorResponse(tc.statusCode, []byte(tc.body))
			if err == nil {
				t.Fatal("handleErrorResponse returned nil error")
			}
			if got := errors.Is(err, ErrAuthRequired); got != tc.wantAuth {
				t.Fatalf("errors.Is(%v, ErrAuthRequired) = %v, want %v", err, got, tc.wantAuth)
			}
			if tc.wantInMessage != "" && !strings.Contains(err.Error(), tc.wantInMessage) {
				t.Fatalf("error %q does not contain %q (detail should be preserved)", err, tc.wantInMessage)
			}
		})
	}
}
