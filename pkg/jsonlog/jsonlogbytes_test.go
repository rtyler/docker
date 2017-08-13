package jsonlog

import (
	"bytes"
	"regexp"
	"testing"
)

func TestJSONLogBytesMarshalJSONBuf(t *testing.T) {
	logs := map[*JSONLogBytes]string{
		{Log: []byte(`"A log line with \\"`)}:           `^{\"log\":\"\\\"A log line with \\\\\\\\\\\"\",\"time\":}$`,
		{Log: []byte("A log line")}:                     `^{\"log\":\"A log line\",\"time\":}$`,
		{Log: []byte("A log line with \r")}:             `^{\"log\":\"A log line with \\r\",\"time\":}$`,
		{Log: []byte("A log line with & < >")}:          `^{\"log\":\"A log line with \\u0026 \\u003c \\u003e\",\"time\":}$`,
		{Log: []byte("A log line with utf8 : 🚀 ψ ω β")}: `^{\"log\":\"A log line with utf8 : 🚀 ψ ω β\",\"time\":}$`,
		{Stream: "stdout"}:                              `^{\"stream\":\"stdout\",\"time\":}$`,
		{Stream: "stdout", Log: []byte("A log line")}:   `^{\"log\":\"A log line\",\"stream\":\"stdout\",\"time\":}$`,
		{Created: "time"}:                               `^{\"time\":time}$`,
		{}:                                              `^{\"time\":}$`,
		// These ones are a little weird
		{Log: []byte("\u2028 \u2029")}: `^{\"log\":\"\\u2028 \\u2029\",\"time\":}$`,
		{Log: []byte{0xaF}}:            `^{\"log\":\"\\ufffd\",\"time\":}$`,
		{Log: []byte{0x7F}}:            `^{\"log\":\"\x7f\",\"time\":}$`,
	}
	for jsonLog, expression := range logs {
		var buf bytes.Buffer
		if err := jsonLog.MarshalJSONBuf(&buf); err != nil {
			t.Fatal(err)
		}
		res := buf.String()
		t.Logf("Result of WriteLog: %q", res)
		logRe := regexp.MustCompile(expression)
		if !logRe.MatchString(res) {
			t.Fatalf("Log line not in expected format [%v]: %q", expression, res)
		}
	}
}
