// Package exec is the single subprocess choke point every external-tool call
// in the harness flows through. Run puts a hard deadline on a command, drains
// stdout/stderr concurrently, kills a hung child, and returns a distinct
// ErrTimeout so a timed-out backend is recorded (the never-silent guard)
// instead of crashing or silently reporting clean. It never spawns a shell —
// commands are argv slices, so repo-derived strings can never be interpolated
// into a command line.
package exec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// ErrTimeout is returned when a command exceeds its deadline. Callers record
// the backend in skipped_reasons (the never-silent guard) instead of crashing.
// It is distinct from the *exec.ExitError a normal non-zero exit returns, so a
// deadline hit is always distinguishable from an ordinary tool failure.
var ErrTimeout = errors.New("exec: command timed out")

// Result is the captured output of one command run. Stdout and Stderr hold the
// fully drained child output, ExitCode is the process exit code (0 unless the
// process started and exited non-zero), and TimedOut is true only when the
// command was killed for exceeding its deadline.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	TimedOut bool
}

// Runner is the injectable seam mirroring the Python injectable-runner
// convention. Higher layers accept a Runner so a hang or timeout can be
// simulated without a real subprocess; Run is the default implementation.
type Runner func(ctx context.Context, timeout time.Duration, name string, args ...string) (Result, error)

// Run executes name+args under a hard timeout. stdout/stderr go to bytes.Buffers,
// which os/exec drains with its own copy goroutines, so a chatty child that
// floods both pipes past the OS buffer never deadlocks. WaitDelay bounds the
// grace period if the child ignores the kill signal, so a wedged process is
// killed and recorded, never blocks the run. A deadline hit returns ErrTimeout
// with Result.TimedOut=true; any other failure returns the underlying error
// (an *exec.ExitError for a non-zero exit). No shell is ever spawned.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()

	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, ErrTimeout
	}
	return res, err
}
