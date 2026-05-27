// Package e2e holds cross-platform end-to-end integration tests for
// era-ocserv's Stage 1 happy path.
//
// All tests live in the external test package (e2e_test) and only
// consume public APIs:
//
//   - internal/cstp.Server   — control-plane handler + binary tunnel
//   - internal/auth.MockVerifier + CertValidator
//   - internal/iam.MockResolver
//   - cmd/era-ocserv         — only the bridge interface shape (tests
//     re-construct the bridge with an in-memory tun on Windows)
//
// The tests deliberately avoid touching the Linux-only internal/tun
// package so they run on Windows, macOS, and Linux without build
// tags. A small in-memory fake (faketun_test.go) substitutes for the
// real device, exercising the same tunQueueIO interface main.go
// wraps the real *tun.Device with.
package e2e
