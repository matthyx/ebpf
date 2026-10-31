//go:build !windows

package link

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
)

func TestKprobeOptionsRetryWithPrefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"success", nil, false},
		{"not-exist", os.ErrNotExist, true},
		{"enoent", unix.ENOENT, true},
		{"einval", unix.EINVAL, true},
		{"wrapped-enoent", fmt.Errorf("wrapped: %w", unix.ENOENT), true},
		{"wrapped-einval", fmt.Errorf("wrapped: %w", unix.EINVAL), true},
		{"not-supported", ErrNotSupported, false},
		{"busy", syscall.EBUSY, false},
		{"permission", unix.EPERM, false},
		{"other", errors.New("other"), false},
	} {
		for _, option := range []struct {
			name  string
			opts  *KprobeOptions
			exact bool
		}{
			{"nil", nil, false},
			{"default", &KprobeOptions{}, false},
			{"exact", &KprobeOptions{ExactSymbol: true}, true},
		} {
			t.Run(tc.name+"/"+option.name, func(t *testing.T) {
				want := tc.retry && !option.exact
				if got := option.opts.retryWithPrefix(tc.err); got != want {
					t.Fatalf("retryWithPrefix(%v) = %v, want %v", tc.err, got, want)
				}
			})
		}
	}
}
