package response

import (
	"bufio"
	"io"
	"net/http"
	"sort"
)

func (g *Guard) wrapStreaming(resp *http.Response) (*http.Response, Result) {
	originalBody := resp.Body
	reader := bufio.NewReader(originalBody)
	pr, pw := io.Pipe()
	collected := map[string]struct{}{}
	notify := func(blocked bool) {
		if len(collected) == 0 && !blocked {
			return
		}
		ids := make([]string, 0, len(collected))
		for id := range collected {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		g.notifyStream(resp.Request, Result{Applied: ids, Blocked: blocked})
	}

	go func() {
		defer originalBody.Close()
		defer pw.Close()
		for {
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				line := chunk
				ids := []string(nil)
				if g.mode == ModeBlock {
					_, highIDs := g.sanitizer.RedactBytes(chunk, true)
					if len(highIDs) > 0 {
						for _, id := range highIDs {
							if id != "" {
								collected[id] = struct{}{}
							}
						}
						notify(true)
						_, _ = pw.Write([]byte("data: {\"error\":\"blocked by agentwall\"}\n\n"))
						return
					}
				}
				line, ids = g.sanitizer.RedactBytes(chunk, false)
				for _, id := range ids {
					if id != "" {
						collected[id] = struct{}{}
					}
				}
				if g.mode == ModeDetect {
					_, _ = pw.Write(chunk)
				} else {
					_, _ = pw.Write(line)
				}
			}
			if err != nil {
				if err == io.EOF {
					notify(false)
					return
				}
				_ = pw.CloseWithError(err)
				return
			}
		}
	}()

	resp.Body = io.NopCloser(pr)
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	return resp, Result{}
}
