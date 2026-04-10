package replay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

type Player struct {
	mu        sync.Mutex
	responses map[string]Entry
}

func Load(path string) (*Player, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := &Player{responses: map[string]Entry{}}
	dec := json.NewDecoder(f)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}
		if e.Kind == "response" {
			p.responses[e.Key] = e
		}
	}
	return p, nil
}

func (p *Player) FindResponse(req *http.Request, body []byte) (Entry, bool) {
	if p == nil || req == nil {
		return Entry{}, false
	}
	key := RequestKey(req.Method, req.URL.String(), body)
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.responses[key]
	if !ok {
		return Entry{}, false
	}
	return entry, true
}

type ReplayTransport struct {
	Player *Player
}

func (t *ReplayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.Player == nil {
		return nil, errors.New("replay transport not initialized")
	}
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	entry, ok := t.Player.FindResponse(req, body)
	if !ok {
		return nil, fmt.Errorf("replay missing response for %s %s", req.Method, req.URL.String())
	}
	if entry.Error != "" {
		return nil, errors.New(entry.Error)
	}
	resp := &http.Response{
		StatusCode:    entry.StatusCode,
		Status:        fmt.Sprintf("%d %s", entry.StatusCode, http.StatusText(entry.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        cloneHeader(entry.Headers),
		Body:          io.NopCloser(bytes.NewReader(entry.Body)),
		ContentLength: int64(len(entry.Body)),
		Request:       req,
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	return resp, nil
}
