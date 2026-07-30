package exec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

// floodN is the per-stream byte count the flood helper emits. It is comfortably
// larger than a typical 64KiB OS pipe buffer so a non-draining reader would
// deadlock — proving os/exec's concurrent bytes.Buffer drain.
const floodN = 256 * 1024

// helperEnv selects the child behavior when the test binary is re-exec'd as its
// own subprocess. Run leaves cmd.Env nil, so the child inherits this from t.Setenv.
const helperEnv = "GO_EXEC_HELPER_MODE"

// TestExecHelperProcess is the hermetic child. When GO_EXEC_HELPER_MODE is set,
// the test binary (re-exec'd via os.Args[0]) acts as a controllable subprocess
// and os.Exits directly so no go-test summary pollutes stdout/stderr. When the
// env var is unset it is an ordinary no-op test.
func TestExecHelperProcess(t *testing.T) {
	switch os.Getenv(helperEnv) {
	case "sleep":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "exit1":
		os.Exit(1)
	case "exit0":
		os.Exit(0)
	case "flood":
		buf := bytes.Repeat([]byte("x"), floodN)
		os.Stdout.Write(buf)
		os.Stderr.Write(buf)
		os.Exit(0)
	default:
		// Normal test invocation — nothing to do.
	}
}

// selfExec runs the test binary as a child in the given helper mode.
func selfExec(t *testing.T, mode string, timeout time.Duration) (Result, error) {
	t.Helper()
	t.Setenv(helperEnv, mode)
	return Run(context.Background(), timeout, os.Args[0], "-test.run=^TestExecHelperProcess$")
}

func TestTimeout(t *testing.T) {
	before := runtime.NumGoroutine()

	start := time.Now()
	res, err := selfExec(t, "sleep", 100*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("want Result.TimedOut=true")
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("hang not cut short: elapsed %v for a 100ms timeout", elapsed)
	}

	// Goroutine-leak check: lenient, timing-sensitive. Assert it does not grow
	// by more than a couple after a short settle.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if grew := runtime.NumGoroutine() - before; grew > 3 {
		t.Fatalf("goroutine count grew by %d (leak?)", grew)
	}
}

func TestExitVsTimeout(t *testing.T) {
	// Non-zero exit: a real failure, NOT a timeout.
	res, err := selfExec(t, "exit1", 10*time.Second)
	if err == nil {
		t.Fatalf("want non-nil error for exit 1")
	}
	if errors.Is(err, ErrTimeout) {
		t.Fatalf("exit 1 must not be classified as ErrTimeout")
	}
	if res.ExitCode != 1 {
		t.Fatalf("want ExitCode 1, got %d", res.ExitCode)
	}
	if res.TimedOut {
		t.Fatalf("exit 1 must not set TimedOut")
	}

	// Clean exit: nil error, ExitCode 0.
	res, err = selfExec(t, "exit0", 10*time.Second)
	if err != nil {
		t.Fatalf("want nil error for exit 0, got %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("want ExitCode 0, got %d", res.ExitCode)
	}
}

func TestDrain(t *testing.T) {
	res, err := selfExec(t, "flood", 10*time.Second)
	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	if len(res.Stdout) != floodN {
		t.Fatalf("stdout: want %d bytes, got %d", floodN, len(res.Stdout))
	}
	if len(res.Stderr) != floodN {
		t.Fatalf("stderr: want %d bytes, got %d", floodN, len(res.Stderr))
	}
}
