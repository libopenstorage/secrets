package api

import (
	"fmt"
)

type ErrorResponse struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type APIError struct {
	message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API Error: %s", e.message)
}

func NewAPIError(body []byte) error {
	message := string(body)

	errResp := new(ErrorResponse)
	if err := jsonUnmarshal(body, errResp); err == nil && errResp.Description != "" {
		message = errResp.Description
	}

	return &APIError{
		message: message,
	}
}
