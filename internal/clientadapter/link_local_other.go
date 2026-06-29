//go:build !darwin

package clientadapter

func autoAssignLinkLocal(_ string) error { return nil }
