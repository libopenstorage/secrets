package kp

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Logger writes when called.
type Logger interface {
	Info(...interface{})
}

type logger struct {
	writer func(...interface{})
}

func (l *logger) Info(args ...interface{}) {
	l.writer(args...)
}

func NewLogger(writer func(...interface{})) Logger {
	return &logger{writer: writer}
}

// dumpFailOnly calls dumpAll when the HTTP response isn't 200 (ok),
// 201 (created), or 204 (no content).
func dumpFailOnly(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log Logger, redactStrings []string) {
	switch rsp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return
	}
	dumpAll(req, rsp, reqBody, resBody, log, redactStrings)
}

// dumpAll dumps the HTTP request and the HTTP response body.
func dumpAll(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log Logger, redactStrings []string) {
	dumpRequest(req, rsp, log, redactStrings, redact)
	dumpBody(reqBody, resBody, log, redactStrings, redact)
}

// dumpAllNoRedact dumps the HTTP request and HTTP response body without redaction.
func dumpAllNoRedact(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log Logger, redactStrings []string) {
	dumpRequest(req, rsp, log, redactStrings, noredact)
	dumpBody(reqBody, resBody, log, redactStrings, noredact)
}

// dumpBodyOnly dumps the HTTP response body.
func dumpBodyOnly(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log Logger, redactStrings []string) {
	dumpBody(reqBody, resBody, log, redactStrings, redact)
}

// dumpNone does nothing.
func dumpNone(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log Logger, redactStrings []string) {
}

// dumpRequest dumps the HTTP request.
func dumpRequest(req *http.Request, rsp *http.Response, log Logger, redactStrings []string, redact Redact) {
	// log.Info(redact(fmt.Sprint(req), redactStrings))
	// log.Info(redact(fmt.Sprint(rsp), redactStrings))
}

// dumpBody dumps the HTTP response body with redactions.
func dumpBody(reqBody, resBody []byte, log Logger, redactStrings []string, redact Redact) {
	// log.Info(string(redact(string(reqBody), redactStrings)))
	// Redact the access token and refresh token if it shows up in the reponnse body.  This will happen
	// when using an API Key
	var auth AuthToken
	if strings.Contains(string(resBody), "access_token") {
		err := json.Unmarshal(resBody, &auth)
		if err != nil {
			log.Info(err)
		}
		redactStrings = append(redactStrings, auth.AccessToken)
		redactStrings = append(redactStrings, auth.RefreshToken)
	}
	// log.Info(string(redact(string(resBody), redactStrings)))
}

// redact replaces substrings within the given string.
func redact(s string, redactStrings []string) string {
	if len(redactStrings) < 1 {
		return s
	}
	var a []string
	for _, s1 := range redactStrings {
		if s1 != "" {
			a = append(a, s1)
			a = append(a, "***Value redacted***")
		}
	}
	r := strings.NewReplacer(a...)
	return r.Replace(s)
}

// noredact does not perform redaction, and returns the given string.
func noredact(s string, redactStrings []string) string {
	return s
}
