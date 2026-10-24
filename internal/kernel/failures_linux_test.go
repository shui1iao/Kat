//go:build linux

package kernel

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestFailureNonblockingSinkHelper(t *testing.T) {
	if os.Getenv("KAT_FAILURE_SINK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	w, c := diagnosticStderr()
	defer c()
	start := time.Now()
	blocked := false
	for i := 0; i < 10000; i++ {
		if e := w(bytes.Repeat([]byte{'x'}, 200)); e != nil {
			blocked = true
			break
		}
	}
	WriteDiagnosticLine("kat event=stopped\n")
	if !blocked || time.Since(start) > time.Second {
		t.Fatal("full stderr did not fail promptly")
	}
}
func TestFailureFullStderrCannotBlockForwarder(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFailureNonblockingSinkHelper$")
	cmd.Env = append(os.Environ(), "KAT_FAILURE_SINK_HELPER=1")
	cmd.Stderr = w
	var out bytes.Buffer
	cmd.Stdout = &out
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("helper failed", out.String())
		}
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("blocked stderr")
	}
}

func TestFailureJournalSocketAndRegularFile(t *testing.T) {
	// The same nonblocking helper must also work when systemd supplies a socket.
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	r := os.NewFile(uintptr(fds[0]), "journal-reader")
	w := os.NewFile(uintptr(fds[1]), "journal-writer")
	defer r.Close()
	defer w.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFailureNonblockingSinkHelper$")
	cmd.Env = append(os.Environ(), "KAT_FAILURE_SINK_HELPER=1")
	cmd.Stderr = w
	done := make(chan error, 1)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("journal socket helper", e)
		}
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("blocked journal")
	}
	f, e := os.CreateTemp(t.TempDir(), "stderr")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	cmd = exec.Command(os.Args[0], "-test.run=^TestFailureFileOffsetHelper$")
	cmd.Env = append(os.Environ(), "KAT_FAILURE_FILE_HELPER=1")
	cmd.Stderr = f
	if e = cmd.Run(); e != nil {
		t.Fatal(e)
	}
	p, e := os.ReadFile(f.Name())
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(p, []byte("begin\nkat event=failure ")) || !bytes.HasSuffix(p, []byte("end\n")) {
		t.Fatal("stderr file offsets corrupted", string(p))
	}
}
func TestFailureFileOffsetHelper(t *testing.T) {
	if os.Getenv("KAT_FAILURE_FILE_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	_, _ = os.Stderr.WriteString("begin\n")
	l := newFailureLog()
	l.emit(failTLS, "anytls", 0, time.Now())
	l.shutdown()
	_, _ = os.Stderr.WriteString("end\n")
}
