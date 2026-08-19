package btf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestCacheModuleRebaseAcrossKernelSpecReload deterministically reproduces the
// race described in armosec/private-node-agent#511: a Cache's kernel spec is
// captured once (as in a long-lived per-gadget Cache), the global weak-pointer
// kernel cache is then invalidated and repopulated (as happens when the GC
// collects it, or another Cache instance's concurrent load races the reload),
// and a subsequent Module() call rebases the freshly (re)loaded module BTF
// against the Cache's now-stale kernel spec.
//
// Both kernel spec instances are read from the same underlying file, so their
// content is always identical -- the two loads only ever differ in the
// identity of the backing byte slice. Before the fix, rebaseDecoder rejects
// this as "raw BTF differs" purely on pointer identity, exactly reproducing
// "apply CO-RE relocations: load BTF for kmod kvm_intel: rebase split spec:
// raw BTF differs" for a real split-BTF kernel module.
func TestCacheModuleRebaseAcrossKernelSpecReload(t *testing.T) {
	// kvm_intel matches private-node-agent#511's exact environment; kvm_amd
	// is the equivalent on AMD-hosted kernels. Either exercises the same
	// split-BTF rebase path.
	module := ""
	for _, candidate := range []string{"kvm_intel", "kvm_amd"} {
		if _, err := os.Stat("/sys/kernel/btf/" + candidate); err == nil {
			module = candidate
			break
		}
	}
	if module == "" {
		t.Skip("no split-BTF kernel module (kvm_intel/kvm_amd) present under /sys/kernel/btf")
	}

	FlushKernelSpec()
	t.Cleanup(FlushKernelSpec)

	c := NewCache()

	// Capture the kernel spec into this Cache instance (V1). This mirrors a
	// gadget's long-lived per-load Cache that calls Kernel() once and reuses
	// the result across Module() calls.
	_, err := c.Kernel()
	testSkipIfNotSupportedBTF(t, err)
	qt.Assert(t, qt.IsNil(err))

	// Simulate the global weak-pointer kernel cache being GC'd and needing a
	// reload -- exactly what globalCache.kernel going through
	// weak.Pointer.Value() == nil produces. The next global load reads the
	// same file again, producing a byte-identical but distinct []byte (V2).
	FlushKernelSpec()

	// Module() rebases the module BTF -- loaded fresh against the now-reloaded
	// global kernel spec (V2) -- against this Cache's stale kernel spec (V1).
	// V1 and V2 have identical content (same file) but different array
	// identity, which is exactly the bug: a content-equal rebase target
	// rejected purely because it isn't the same backing array.
	_, err = c.Module(module)
	if os.IsNotExist(err) {
		t.Skipf("module %s has no BTF on this kernel", module)
	}
	qt.Assert(t, qt.IsNil(err),
		qt.Commentf("Module() rebase must succeed against content-identical kernel BTF "+
			"reloaded into a new backing array (private-node-agent#511)"))
}

func testSkipIfNotSupportedBTF(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Skipf("BTF not supported on this kernel: %v", err)
	}
}
