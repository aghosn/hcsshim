package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControllerAuthenticationAndInput(t *testing.T) {
	c := &controller{token: "test-only", seen: map[string]bool{}, active: "already-active"}
	for _, tc := range []struct {
		path, body, token string
		want              int
	}{
		{"/begin", `{"id":"trial-1"}`, "", http.StatusUnauthorized},
		{"/begin", `{"id":"../../file"}`, "test-only", http.StatusBadRequest},
		{"/begin", `{"id":"trial-1","args":["unsafe"]}`, "test-only", http.StatusBadRequest},
		{"/begin", `{"id":"trial-1"} {}`, "test-only", http.StatusBadRequest},
		{"/begin", `{"id":"trial-1"}`, "test-only", http.StatusConflict},
		{"/end", `{"id":"wrong-trial"}`, "test-only", http.StatusConflict},
		{"/unknown", `{}`, "test-only", http.StatusMethodNotAllowed},
	} {
		r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s: status=%d, want=%d: %s", tc.path, tc.body, w.Code, tc.want, w.Body)
		}
	}
}

func TestListenerReadinessAcrossWrites(t *testing.T) {
	out := &capturedOutput{ready: make(chan struct{})}
	for _, s := range []string{"Server listening on TCP", " port 5201\n", "data\n"} {
		if _, err := out.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-out.ready:
	default:
		t.Fatal("listener never became ready")
	}
	if !strings.Contains(out.String(), "data\n") {
		t.Fatal("receiver output was lost")
	}
}

func TestControllerStatusIsAuthenticatedAndDoesNotStopTrial(t *testing.T) {
	c := &controller{token: "test-only", active: "own-trial"}
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.Header.Set("Authorization", "Bearer "+c.token)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"active_id":"own-trial"`) || c.active != "own-trial" {
		t.Fatalf("status modified the trial or returned incorrect state: %d %s", w.Code, w.Body)
	}
}
