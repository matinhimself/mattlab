package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Headers that should be skipped when forwarding through relay.
var skipHeaders = map[string]bool{
	"host": true, "connection": true, "proxy-connection": true,
	"keep-alive": true, "transfer-encoding": true, "te": true,
	"trailer": true, "upgrade": true, "content-length": true,
}

// Payload holds the serialized relay request payload.
type Payload struct {
	Body        []byte
	ContentType string
	Format      string // "form" or "json"
	TargetURL   string // original URL being relayed
}

// BuildFormPayload builds a form-urlencoded payload for google_relay.js.
func BuildFormPayload(method, targetURL string, headers map[string]string, body []byte) *Payload {
	fields := url.Values{}
	fields.Set("url", targetURL)
	fields.Set("method", method)

	fwd := make(map[string]string)
	for k, v := range headers {
		if !skipHeaders[strings.ToLower(k)] {
			fwd[k] = v
		}
	}
	if len(fwd) > 0 {
		hjson, _ := json.Marshal(fwd)
		fields.Set("headers", string(hjson))
	}

	if len(body) > 0 && (method == "POST" || method == "PUT" || method == "PATCH") {
		fields.Set("body", base64.StdEncoding.EncodeToString(body))
		fields.Set("bodyEncoding", "base64")
	}

	if ct, ok := headers["content-type"]; ok {
		fields.Set("contentType", ct)
	} else if ct, ok := headers["Content-Type"]; ok {
		fields.Set("contentType", ct)
	}

	return &Payload{
		Body:        []byte(fields.Encode()),
		ContentType: "application/x-www-form-urlencoded",
		Format:      "form",
		TargetURL:   targetURL,
	}
}

// BuildJSONPayload builds a JSON payload for MasterHttpRelayVPN Code.gs.
func BuildJSONPayload(method, targetURL string, headers map[string]string, body []byte, authKey string) *Payload {
	obj := map[string]interface{}{
		"m": method,
		"u": targetURL,
		"r": false,
	}

	if len(headers) > 0 {
		filt := make(map[string]string)
		for k, v := range headers {
			if strings.ToLower(k) != "accept-encoding" {
				filt[k] = v
			}
		}
		obj["h"] = filt
	}

	if len(body) > 0 {
		obj["b"] = base64.StdEncoding.EncodeToString(body)
		if ct, ok := headers["Content-Type"]; ok {
			obj["ct"] = ct
		} else if ct, ok := headers["content-type"]; ok {
			obj["ct"] = ct
		}
	}

	obj["k"] = authKey

	jsonBody, _ := json.Marshal(obj)

	return &Payload{
		Body:        jsonBody,
		ContentType: "application/json",
		Format:      "json",
		TargetURL:   targetURL,
	}
}

// ParseRelayResponse parses the JSON response from the relay server into
// raw HTTP/1.1 response bytes.
func ParseRelayResponse(body []byte, format string) ([]byte, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return errorResponse(502, "Empty relay response"), nil
	}

	// Try to extract JSON from potentially messy response
	jsonStart := strings.Index(text, "{")
	jsonEnd := strings.LastIndex(text, "}")
	if jsonStart < 0 || jsonEnd < 0 {
		return errorResponse(502, "No JSON in response: "+truncate(text, 200)), nil
	}

	var data map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text[jsonStart:jsonEnd+1]), &data); err != nil {
		return errorResponse(502, "Bad JSON: "+truncate(text, 200)), nil
	}

	// Check for error in either format
	if e, ok := data["error"]; ok {
		return errorResponse(502, "Relay error: "+string(e)), nil
	}
	if e, ok := data["e"]; ok {
		return errorResponse(502, "Relay error: "+string(e)), nil
	}

	// Form format (google_relay.js) uses "status"
	if _, ok := data["status"]; ok {
		return parseFormResponse(data), nil
	}

	// JSON format (MasterHttpRelayVPN) uses "s"
	if _, ok := data["s"]; ok {
		return parseJSONResponse(data), nil
	}

	return errorResponse(502, "Unknown response format: "+truncate(text, 200)), nil
}

func parseFormResponse(data map[string]json.RawMessage) []byte {
	var status int
	json.Unmarshal(data["status"], &status)
	if status == 0 {
		status = 200
	}

	var contentType string
	json.Unmarshal(data["contentType"], &contentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	var encoding string
	json.Unmarshal(data["encoding"], &encoding)

	var respHeaders map[string]string
	json.Unmarshal(data["headers"], &respHeaders)

	var bodyRaw json.RawMessage
	json.Unmarshal(data["body"], &bodyRaw)

	var respBody []byte
	if encoding == "base64" {
		respBody, _ = base64.StdEncoding.DecodeString(string(bodyRaw))
	} else {
		respBody = []byte(bodyRaw)
	}

	// Build HTTP response
	var b strings.Builder
	statusText := httpStatusText(status)
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText)
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)

	skip := map[string]bool{"transfer-encoding": true, "connection": true, "content-length": true, "content-type": true}
	for k, v := range respHeaders {
		if !skip[strings.ToLower(k)] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}

	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(respBody))
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")

	return append([]byte(b.String()), respBody...)
}

func parseJSONResponse(data map[string]json.RawMessage) []byte {
	var status int
	json.Unmarshal(data["s"], &status)
	if status == 0 {
		status = 200
	}

	var respHeaders map[string]json.RawMessage
	json.Unmarshal(data["h"], &respHeaders)

	var bodyB64 string
	json.Unmarshal(data["b"], &bodyB64)
	respBody, _ := base64.StdEncoding.DecodeString(bodyB64)

	var b strings.Builder
	statusText := httpStatusText(status)
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText)

	skip := map[string]bool{"transfer-encoding": true, "connection": true, "keep-alive": true, "content-length": true, "content-encoding": true}
	for k, rawV := range respHeaders {
		if skip[strings.ToLower(k)] {
			continue
		}
		// Value can be string or array
		var s string
		if err := json.Unmarshal(rawV, &s); err == nil {
			fmt.Fprintf(&b, "%s: %s\r\n", k, s)
		} else {
			var arr []string
			if json.Unmarshal(rawV, &arr) == nil {
				for _, v := range arr {
					fmt.Fprintf(&b, "%s: %s\r\n", k, v)
				}
			}
		}
	}

	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(respBody))
	b.WriteString("\r\n")

	return append([]byte(b.String()), respBody...)
}

func errorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, len(body), body,
	))
}

func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 206:
		return "Partial Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	default:
		return "OK"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
