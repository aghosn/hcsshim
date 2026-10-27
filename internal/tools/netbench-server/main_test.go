package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if marker := os.Getenv("NETBENCH_TEST_EXIT_MARKER"); marker != "" {
		fmt.Println("Server listening on TCP port fixture")
		for {
			_, err := os.Stat(marker)
			if err == nil && strings.Contains(strings.Join(os.Args, " "), "-p 5202") {
				code, err := strconv.Atoi(os.Getenv("NETBENCH_TEST_EXIT_CODE"))
				if err != nil {
					panic(err)
				}
				os.Exit(code)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	os.Exit(m.Run())
}

func TestControllerAuthenticationAndInput(t *testing.T) {
	c := &controller{token: "test-only", seen: map[string]bool{}, active: "already-active"}
	for _, tc := range []struct {
		path, body, token string
		want              int
	}{
		{"/begin", `{"id":"trial-1"}`, "", http.StatusUnauthorized},
		{"/begin", `{"id":"../../file"}`, "test-only", http.StatusBadRequest},
		{"/begin", `{"id":"trial-1","args":["unsafe"]}`, "test-only", http.StatusBadRequest},
		{"/begin", `{"id":"trial-1","primary_latency":"true"}`, "test-only", http.StatusBadRequest},
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

func TestListenerArgsSeparateLatencyFromBulkReporting(t *testing.T) {
	base := []string{"-s", "-B", "192.0.2.10", "-p", "5201", "-e", "-f", "m", "--utc"}
	bulkOptions := []string{"-i", "1"}
	if runtime.GOOS == "windows" {
		bulkOptions = []string{"-t", "600"}
	}
	for _, tc := range []struct {
		latency bool
		options []string
	}{
		{false, bulkOptions},
		{true, []string{"-t", "600"}},
	} {
		want := append(append([]string{}, base...), tc.options...)
		if got := listenerArgs("192.0.2.10", 5201, tc.latency); !reflect.DeepEqual(got, want) {
			t.Fatalf("latency=%v: arguments=%v, want=%v", tc.latency, got, want)
		}
	}
}

func TestControllerHealthReportsListenerProtocol(t *testing.T) {
	c := &controller{token: "test-only"}
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.Header.Set("Authorization", "Bearer "+c.token)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	var health struct {
		Protocol int `json:"protocol"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || health.Protocol != 3 {
		t.Fatalf("unexpected protocol: status=%d body=%s", w.Code, w.Body)
	}
}

func controlRequest(c *controller, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+c.token)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}

func TestControllerCompletedResultRetrieval(t *testing.T) {
	c := &controller{token: "test-only", lastResult: &trialResult{ID: "failed-trial", Failure: "original error"}}
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/result?id=../../file", http.StatusBadRequest},
		{"/result?id=unknown-trial", http.StatusNotFound},
		{"/result?id=failed-trial", http.StatusOK},
	} {
		w := controlRequest(c, http.MethodGet, tc.path, "")
		if w.Code != tc.want {
			t.Fatalf("%s: status=%d body=%s", tc.path, w.Code, w.Body)
		}
		if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), "original error") {
			t.Fatal("completed result lost the original failure")
		}
	}
	c.active = "failed-trial"
	if w := controlRequest(c, http.MethodGet, "/result?id=failed-trial", ""); w.Code != http.StatusConflict {
		t.Fatal("returned the old result while its retry was active")
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/result?id=failed-trial", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("completed result retrieval bypassed authentication")
	}
}

func TestControllerServerCrashRetry(t *testing.T) {
	for _, tc := range []struct {
		name        string
		exitCode    uint32
		crashAgain  bool
		saveFailure bool
	}{
		{name: "access-violation", exitCode: 0xc0000005},
		{name: "repeated-access-violation", exitCode: 0xc0000005, crashAgain: true},
		{name: "other-error", exitCode: 17},
		{name: "preserve-failure", exitCode: 0xc0000005, saveFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "exit")
			t.Setenv("NETBENCH_TEST_EXIT_MARKER", marker)
			t.Setenv("NETBENCH_TEST_EXIT_CODE", strconv.FormatUint(uint64(tc.exitCode), 10))
			c := &controller{token: "test-only", binary: os.Args[0], bind: "192.0.2.10",
				port: 5201, output: root, seen: map[string]bool{}}
			defer func() {
				if c.active != "" {
					c.finish("test cleanup")
				}
			}()
			begin := func(retry bool) *httptest.ResponseRecorder {
				return controlRequest(c, http.MethodPost, "/begin",
					fmt.Sprintf(`{"id":"crash-trial","primary_latency":true,"retry":%t}`, retry))
			}
			crash := func() {
				t.Helper()
				if err := os.WriteFile(marker, nil, 0600); err != nil {
					t.Fatal(err)
				}
				select {
				case <-c.servers[1].done:
				case <-time.After(5 * time.Second):
					t.Fatal("fixture listener did not exit")
				}
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}
			end := func() *httptest.ResponseRecorder {
				return controlRequest(c, http.MethodPost, "/end", `{"id":"crash-trial"}`)
			}
			if w := begin(false); w.Code != http.StatusOK {
				t.Fatalf("begin: %d %s", w.Code, w.Body)
			}
			crash()
			if w := end(); w.Code != http.StatusInternalServerError {
				t.Fatalf("crashed listener was accepted: %d %s", w.Code, w.Body)
			}
			eligible := runtime.GOOS == "windows" && tc.exitCode == 0xc0000005
			if got := c.lastResult.FailureKind == accessViolation; got != eligible {
				t.Fatalf("retry eligibility=%v want=%v: %+v", got, eligible, c.lastResult)
			}
			if w := begin(false); w.Code != http.StatusConflict {
				t.Fatal("duplicate ID was accepted without an explicit retry")
			}
			archive := filepath.Join(root, "crash-trial.failed-attempt-0.json")
			if tc.saveFailure {
				if err := os.WriteFile(archive, []byte("existing evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := begin(true)
			if !eligible {
				if w.Code != http.StatusConflict {
					t.Fatal("retried a failure other than a Windows bulk access violation")
				}
				return
			}
			if tc.saveFailure {
				if w.Code != http.StatusInternalServerError || c.active != "" {
					t.Fatal("started retry without preserving failed-attempt evidence")
				}
				data, err := os.ReadFile(archive)
				if err != nil || string(data) != "existing evidence" {
					t.Fatal("overwrote existing failed-attempt evidence")
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("eligible retry rejected: %d %s", w.Code, w.Body)
			}
			data, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			var first trialResult
			if err := json.Unmarshal(data, &first); err != nil || first.FailureKind != accessViolation ||
				first.Attempt != 0 || first.ID != "crash-trial" {
				t.Fatalf("failed attempt not preserved: %s (%v)", data, err)
			}
			if tc.crashAgain {
				crash()
			}
			want := http.StatusOK
			if tc.crashAgain {
				want = http.StatusInternalServerError
			}
			if w := end(); w.Code != want || c.lastResult.Attempt != 1 {
				t.Fatalf("retry outcome: %d %s", w.Code, w.Body)
			}
			if w := begin(true); w.Code != http.StatusConflict {
				t.Fatal("allowed more than one retry")
			}
		})
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
