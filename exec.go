package ifac

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	commandTimeout = 15 * time.Second

	// commandWaitDelay bounds how long run waits for a killed command's
	// stderr pipe to close, which a lingering grandchild could hold open.
	commandWaitDelay = 2 * time.Second
)

// run executes a system configuration command, folding stderr into the
// returned error so failures are diagnosable. A bounded runtime prevents a
// stuck platform utility from hanging Up or Down indefinitely.
func run(bin string, args ...string) error {
	return runEnv(nil, bin, args...)
}

// runEnv is run with extra KEY=value pairs appended to the environment.
func runEnv(env []string, bin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = commandWaitDelay
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), ctx.Err())
		}
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return nil
}
