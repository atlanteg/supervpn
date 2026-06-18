//go:build !windows

package bridge

// ifaceHasLink is a no-op on non-Windows platforms, where net.FlagUp already
// reflects the operational (media-connected) state.
func ifaceHasLink(string) bool { return true }
