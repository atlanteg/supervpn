//go:build !windows

package bridge

// ifaceHasLink is a no-op on non-Windows platforms, where net.FlagUp already
// reflects the operational (media-connected) state.
func ifaceHasLink(string) bool { return true }

// adapterDescription has no portable equivalent off Windows; the friendly-name
// check in IsExcludedFromBridge is sufficient there.
func adapterDescription(string) string { return "" }
