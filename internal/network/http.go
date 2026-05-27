package network

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPResult holds the outcome of an HTTP probe.
type HTTPResult struct {
	URL        string
	StatusCode int
	Duration   time.Duration
	Headers    http.Header
	BodySize   int64
	Error      error
}

// ProbeHTTP performs an HTTP GET request and measures response time.
func ProbeHTTP(ctx context.Context, url string) *HTTPResult {
	start := time.Now()

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &HTTPResult{
			URL:      url,
			Duration: time.Since(start),
			Error:    fmt.Errorf("creating request: %w", err),
		}
	}

	req.Header.Set("User-Agent", "vdi-diag/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &HTTPResult{
			URL:      url,
			Duration: time.Since(start),
			Error:    fmt.Errorf("executing request: %w", err),
		}
	}
	defer resp.Body.Close()

	bodySize, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(start)

	return &HTTPResult{
		URL:        url,
		StatusCode: resp.StatusCode,
		Duration:   duration,
		Headers:    resp.Header,
		BodySize:   bodySize,
	}
}
