package vlessx

import (
	reality "github.com/xtls/reality"
	"testing"
)

func TestRealityDependencyLoads(t *testing.T) { var _ *reality.Conn; _ = reality.VersionTLS13 }
