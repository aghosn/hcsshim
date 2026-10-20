// netbench-server controls stock iperf2 listeners; it does not generate or
// measure traffic itself. Use only on an isolated benchmark LAN (HTTP, not TLS).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var validID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)

type capturedOutput struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (o *capturedOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.data.Len()+len(p) > 32<<20 {
		return 0, errors.New("iperf server output exceeded 32 MiB")
	}
	n, err := o.data.Write(p)
	if bytes.Contains(o.data.Bytes(), []byte("Server listening on TCP port")) {
		o.once.Do(func() { close(o.ready) })
	}
	return n, err
}

func (o *capturedOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.data.String()
}

type listener struct {
	cmd  *exec.Cmd
	out  *capturedOutput
	done chan struct{}
	err  error
}

func startListener(binary, bind string, port int) (*listener, error) {
	out := &capturedOutput{ready: make(chan struct{})}
	cmd := exec.Command(binary, "-s", "-B", bind, "-p", strconv.Itoa(port), "-e", "-f", "m", "-i", "1", "--utc")
	for _, env := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(env), "IPERF_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	l := &listener{cmd: cmd, out: out, done: make(chan struct{})}
	go func() {
		l.err = cmd.Wait()
		close(l.done)
	}()
	select {
	case <-out.ready:
		return l, nil
	case <-l.done:
		return nil, fmt.Errorf("iperf listener exited: %v: %s", l.err, out.String())
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-l.done
		return nil, fmt.Errorf("iperf listener readiness timeout: %s", out.String())
	}
}

func (l *listener) stop() (string, float64, error) {
	var result error
	select {
	case <-l.done:
		result = fmt.Errorf("iperf listener exited unexpectedly: %v", l.err)
	default:
		if err := l.cmd.Process.Kill(); err != nil {
			result = fmt.Errorf("stop iperf listener: %w", err)
		}
		<-l.done
	}
	cpu := l.cmd.ProcessState.UserTime() + l.cmd.ProcessState.SystemTime()
	return l.out.String(), cpu.Seconds(), result
}

type trialResult struct {
	ID            string    `json:"id"`
	StartedUTC    time.Time `json:"started_utc"`
	EndedUTC      time.Time `json:"ended_utc"`
	OS            string    `json:"os"`
	CPUs          int       `json:"cpus"`
	Primary       string    `json:"primary"`
	Load          string    `json:"load"`
	ServerCPUTime float64   `json:"server_cpu_seconds"`
	Failure       string    `json:"failure,omitempty"`
}

type controller struct {
	mu          sync.Mutex
	token       string
	binary      string
	bind        string
	port        int
	output      string
	active      string
	seen        map[string]bool
	started     time.Time
	servers     []*listener
	timer       *time.Timer
	iperfSHA256 string
}

func (c *controller) finish(failure string) trialResult {
	result := trialResult{ID: c.active, StartedUTC: c.started,
		OS: runtime.GOOS, CPUs: runtime.NumCPU(), Failure: failure}
	if c.timer != nil {
		c.timer.Stop()
	}
	for i, server := range c.servers {
		text, cpu, err := server.stop()
		if err != nil {
			result.Failure += "; " + err.Error()
		}
		if i == 0 {
			result.Primary = text
		} else {
			result.Load = text
		}
		result.ServerCPUTime += cpu
	}
	result.EndedUTC = time.Now().UTC()
	data, err := json.MarshalIndent(result, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(c.output, c.active+".json"), data, 0600)
	}
	if err != nil {
		result.Failure += "; save server result: " + err.Error()
	}
	c.active, c.servers = "", nil
	return result
}

func (c *controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol": 1, "os": runtime.GOOS, "cpus": runtime.NumCPU(),
			"iperf_version": "2.2.1", "iperf_sha256": c.iperfSHA256})
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/status" {
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"active_id": c.active})
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/begin" && r.URL.Path != "/end") {
		http.Error(w, "use POST /begin or /end", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || !validID.MatchString(request.ID) {
		http.Error(w, "invalid trial ID", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "unexpected request data", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.URL.Path == "/begin" {
		if c.active != "" || c.seen[request.ID] {
			http.Error(w, "another trial is active or this ID was already used", http.StatusConflict)
			return
		}
		c.active, c.started = request.ID, time.Now().UTC()
		c.seen[request.ID] = true
		for _, port := range []int{c.port, c.port + 1} {
			server, err := startListener(c.binary, c.bind, port)
			if err != nil {
				result := c.finish(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(result)
				return
			}
			c.servers = append(c.servers, server)
		}
		id := c.active
		c.timer = time.AfterFunc(10*time.Minute, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.active == id {
				result := c.finish("trial exceeded the 10-minute server deadline")
				log.Printf("trial %s failed: %s", id, result.Failure)
			}
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"id": c.active, "status": "ready"})
		return
	}
	if request.ID != c.active {
		http.Error(w, "trial is not active", http.StatusConflict)
		return
	}
	result := c.finish("")
	if result.Failure != "" {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_ = json.NewEncoder(w).Encode(result)
}

func main() {
	bind := flag.String("bind", "", "Required LAN IPv4 address; binds HTTP and both iperf2 listeners")
	port := flag.Int("port", 5201, "iperf2 base port; bulk load uses +1 and control HTTP uses +2")
	binary := flag.String("iperf", "", "Path to the bundled stock iperf2 2.2.1 executable")
	output := flag.String("output", "netbench-server-results", "Directory for per-trial receiver logs")
	flag.Parse()
	ip := net.ParseIP(*bind)
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || *port < 1024 || *port > 65533 {
		log.Fatal("-bind must be a unicast LAN IPv4 and -port must be 1024..65533")
	}
	if *binary == "" {
		log.Fatal("-iperf must name the bundled iperf2 executable")
	}
	path, err := filepath.Abs(*binary)
	if err != nil {
		log.Fatal(err)
	}
	version, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("iperf version 2.2.1")) {
		log.Fatalf("expected iperf2 2.2.1: %v: %s", err, version)
	}
	binaryData, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	binarySHA := fmt.Sprintf("%x", sha256.Sum256(binaryData))
	if err := os.MkdirAll(*output, 0700); err != nil {
		log.Fatal(err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		log.Fatal(err)
	}
	c := &controller{token: hex.EncodeToString(secret[:]), binary: path,
		bind: *bind, port: *port, output: *output, seen: map[string]bool{}, iperfSHA256: binarySHA}
	address := net.JoinHostPort(*bind, strconv.Itoa(*port+2))
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Stock %sControl: http://%s (isolated benchmark LAN only; not TLS)\n", version, address)
	fmt.Printf("Enter this one-time token at the Windows experiment prompt: %s\n", c.token)
	fmt.Printf("Allow client-host TCP ports %d, %d, %d; results: %s\n", *port, *port+1, *port+2, *output)
	server := &http.Server{Handler: c, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	go func() {
		<-interrupt
		c.mu.Lock()
		if c.active != "" {
			result := c.finish("server interrupted")
			log.Printf("trial %s interrupted: %s", result.ID, result.Failure)
		}
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
