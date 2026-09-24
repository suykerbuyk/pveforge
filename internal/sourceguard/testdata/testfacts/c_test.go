package testfacts

import (
	"io"
	logpkg "log"
	"os"
	"testing"
)

var (
	counter  int
	registry = map[string]int{}
	cfg      struct{ N *struct{ M int } }
	hook     func()
)

func BenchmarkPlanted(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {})
}

func TestMore(t *testing.T) {
	os.Setenv("X", "1")
	os.Chdir("/")
	logpkg.SetOutput(io.Discard)
	counter++
	registry["k"] = 1
	cfg.N.M = 1
	hook = func() {}
	(*cfg.N).M--
	t.Setenv("Y", "2") // refused by testing itself in a parallel test: not counted
	var local struct{ f int }
	local.f = 3 // a local's field: not counted
	_ = local
}
