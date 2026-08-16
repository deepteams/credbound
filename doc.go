// Package credbound provides transport-independent authentication,
// workspace authorization and instance-administration primitives.
//
// Sensitive mutations and their audit events are committed atomically by the
// Store contract. Server applications remain responsible for sessions, CSRF,
// request throttling and the trusted-loopback decision.
package credbound
