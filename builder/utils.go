package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
)

// SendSSZRequest is a request to send SSZ data to a remote relay.
func SendSSZRequest(ctx context.Context, client http.Client, method, url string, payload []byte, useGzip bool) (code int, err error) {
	var req *http.Request

	reader := bytes.NewReader(payload)

	if useGzip {
		// Create a new gzip writer
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)

		// Write the payload to the gzip writer
		_, err = reader.WriteTo(gzipWriter)
		if err != nil {
			return 0, fmt.Errorf("error writing payload to gzip writer: %w", err)
		}

		// Flush and close the gzip writer to finalize the compressed data
		err = gzipWriter.Close()
		if err != nil {
			return 0, fmt.Errorf("error closing gzip writer: %w", err)
		}

		req, err = http.NewRequest(http.MethodPost, url, &buf)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
		req.Header.Add("Content-Encoding", "gzip")
	} else {
		req, err = http.NewRequest(http.MethodPost, url, reader)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
	}

	req.Header.Add("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("HTTP error response: %d / %s", resp.StatusCode, string(bodyBytes))
	}
	return resp.StatusCode, nil
}
