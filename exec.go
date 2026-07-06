package ifac

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes a system configuration command, folding stderr into the
// returned error so failures are diagnosable.
func run(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return nil
}
