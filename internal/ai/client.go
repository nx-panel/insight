package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nx-panel/addon-kit/telegram"
)

// callTimeout is long: a local model on a small server can take minutes.
const callTimeout = 4 * time.Minute

// Answer is one completion.
type Answer struct {
	Content string
	Tokens  int
}

// Client speaks the OpenAI chat-completions API, which OpenAI, most other
// providers and Ollama (/v1) all answer.
type Client struct {
	// HTTP, when set, is used instead of one built from the settings' proxy
	// (tests).
	HTTP *http.Client
	// plainJSON is set once a provider refused a JSON schema: from then on
	// only a JSON object is asked for, and Parse checks the shape.
	plainJSON atomic.Bool
	// completionTokens is set once a provider refused max_tokens (OpenAI's
	// reasoning models take max_completion_tokens instead).
	completionTokens atomic.Bool
}

// maxAnswer bounds the answer: twenty findings fit well inside it, and a
// small local model that starts repeating itself is cut off instead of
// generating until the timeout.
const maxAnswer = 3000

// errTokensRefused is a provider that does not take max_tokens.
var errTokensRefused = errors.New("max_tokens refused")

// errSchemaRefused is a provider that does not take response_format
// json_schema.
var errSchemaRefused = errors.New("json schema refused")

// Complete sends the system prompt and the table and returns the answer.
func (c *Client) Complete(ctx context.Context, s Settings, user string) (Answer, error) {
	hc := c.HTTP
	if hc == nil {
		var err error
		if hc, err = telegram.HTTPClient(s.Proxy); err != nil {
			return Answer{}, err
		}
		hc.Timeout = callTimeout
		// The address is the admin's, and so is where the key goes: a
		// redirect would send the table, and on the same host the key,
		// somewhere the admin did not name.
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	for range 3 {
		a, err := c.complete(ctx, hc, s, user, !c.plainJSON.Load())
		switch {
		case errors.Is(err, errSchemaRefused):
			c.plainJSON.Store(true)
		case errors.Is(err, errTokensRefused):
			c.completionTokens.Store(true)
		default:
			return a, err
		}
	}
	return Answer{}, errors.New("the provider refused every request shape")
}

func (c *Client) complete(ctx context.Context, hc *http.Client, s Settings, user string, withSchema bool) (Answer, error) {
	format := map[string]any{"type": "json_object"}
	if withSchema {
		format = map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "findings", "strict": true, "schema": schema()}}
	}
	req := map[string]any{
		"model":       s.Model,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": user},
		},
		"response_format": format,
	}
	if c.completionTokens.Load() {
		req["max_completion_tokens"] = maxAnswer
	} else {
		req["max_tokens"] = maxAnswer
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Answer{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if s.Key != "" {
		hreq.Header.Set("Authorization", "Bearer "+s.Key)
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return Answer{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Answer{}, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if resp.StatusCode == http.StatusBadRequest {
			switch {
			case withSchema && (strings.Contains(msg, "response_format") || strings.Contains(msg, "json_schema")):
				return Answer{}, errSchemaRefused
			case !c.completionTokens.Load() && strings.Contains(msg, "max_tokens"):
				return Answer{}, errTokensRefused
			}
		}
		return Answer{}, fmt.Errorf("the provider answered %d: %s", resp.StatusCode, msg)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Answer{}, fmt.Errorf("the provider's answer is not a chat completion: %w", err)
	}
	if len(out.Choices) == 0 {
		return Answer{}, errors.New("the provider's answer has no choices")
	}
	a := Answer{Content: out.Choices[0].Message.Content, Tokens: out.Usage.TotalTokens}
	if a.Tokens == 0 {
		// A provider that reports no usage is charged by length (four bytes
		// a token), so the budget still binds.
		a.Tokens = (len(systemPrompt) + len(user) + len(a.Content)) / 4
	}
	return a, nil
}
