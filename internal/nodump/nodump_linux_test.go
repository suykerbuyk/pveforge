//go:build linux

package nodump

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// childEnv, when set, makes TestSet the child: it calls Set and prints the
// flag the kernel then reports. Set cannot be undone, so it runs in a child
// process and never in the test process itself.
const childEnv = "NODUMP_TEST_CHILD"

func dumpable() (uintptr, error) {
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

func TestSet(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		if err := Set(); err != nil {
			fmt.Println("error:", err)
			return
		}
		d, err := dumpable()
		fmt.Printf("dumpable: %d %v\n", d, err)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSet$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "dumpable: 0 <nil>\n") {
		t.Errorf("child: %v\n%s", err, out)
	}
	// Anti-vacuity: a process that did not call Set is dumpable.
	if d, err := dumpable(); err != nil || d != 1 {
		t.Errorf("this test process reports dumpable %d (%v): the child's 0 proves nothing", d, err)
	}
}
