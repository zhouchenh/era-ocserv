package auth

import "regexp"

// deviceIDRE matches ERA's idgen device-id shape: the literal prefix
// "dev_" followed by exactly 26 lowercase base32 characters (RFC 4648,
// alphabet [a-z2-7], no padding). Source of truth: idgen.New("dev")
// in github.com/zhouchenh/tpm/internal/idgen.
var deviceIDRE = regexp.MustCompile(`^dev_[a-z2-7]{26}$`)

// validDeviceID reports whether s is shaped like a device UUID issued
// by ERA's idgen.
func validDeviceID(s string) bool { return deviceIDRE.MatchString(s) }
