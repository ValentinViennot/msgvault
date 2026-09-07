package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type actingUserContextKey struct{}

type actingIdentityContextKey struct{}

// WithActingUser marks a request as made on behalf of the user with this
// address. A service that authenticates with its own credential (the MCP
// sidecar) sets it so the daemon applies that user's role and visibility.
func WithActingUser(ctx context.Context, email string) context.Context {
	if email == "" {
		return ctx
	}
	return context.WithValue(ctx, actingUserContextKey{}, email)
}

// ActingUser returns the address set by WithActingUser, if any.
func ActingUser(ctx context.Context) string {
	email, _ := ctx.Value(actingUserContextKey{}).(string)
	return email
}

// ActingUserHeader carries the acting user between a service and the daemon.
// The daemon honours it only from keys configured with on_behalf_of.
const ActingUserHeader = "X-Msgvault-On-Behalf-Of"

// ActingIdentityHeader carries what the service verified about the acting
// user: the identity-provider account behind the address in ActingUserHeader
// and the role the service derived from the provider's groups. Its value is
// the JSON form of ActingIdentity on one line of printable ASCII. The daemon
// honours it only beside ActingUserHeader from a key configured with
// on_behalf_of, and records it as a sign-in the way the browser login does,
// so a person the daemon has never seen becomes a user on first use.
const ActingIdentityHeader = "X-Msgvault-On-Behalf-Of-Identity"

// ErrActingIdentityInvalid reports an ActingIdentityHeader value a daemon
// must not trust: malformed, oversized, without an account, or with an
// unknown role.
var ErrActingIdentityInvalid = errors.New("invalid acting identity")

const (
	// actingIdentityMaxHeader bounds the header value a daemon parses.
	actingIdentityMaxHeader = 4096
	// actingIdentityMaxAccount bounds the issuer and the subject.
	actingIdentityMaxAccount = 512
	// actingIdentityMaxName bounds the display name, in bytes.
	actingIdentityMaxName = 256
)

// ActingIdentity is the verified identity a trusted service asserts for the
// acting user. Issuer and Subject name the identity-provider account, Role is
// the role the service derived from the provider's groups, and Name is the
// display name when the provider supplied one.
type ActingIdentity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
	Role    Role   `json:"role"`
}

// WithActingIdentity records what the service verified about the acting user
// named by WithActingUser.
func WithActingIdentity(ctx context.Context, identity ActingIdentity) context.Context {
	return context.WithValue(ctx, actingIdentityContextKey{}, identity)
}

// ActingIdentityFromContext returns the identity set by WithActingIdentity.
func ActingIdentityFromContext(ctx context.Context) (ActingIdentity, bool) {
	identity, ok := ctx.Value(actingIdentityContextKey{}).(ActingIdentity)
	return identity, ok
}

// Validate reports whether a daemon may act on the identity.
func (id ActingIdentity) Validate() error {
	if strings.TrimSpace(id.Issuer) == "" || strings.TrimSpace(id.Subject) == "" {
		return fmt.Errorf("%w: issuer and subject are required", ErrActingIdentityInvalid)
	}
	fields := []struct {
		name, value string
		max         int
	}{
		{"issuer", id.Issuer, actingIdentityMaxAccount},
		{"subject", id.Subject, actingIdentityMaxAccount},
		{"name", id.Name, actingIdentityMaxName},
	}
	for _, field := range fields {
		if len(field.value) > field.max {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrActingIdentityInvalid, field.name, field.max)
		}
		if !utf8.ValidString(field.value) || strings.ContainsFunc(field.value, unicode.IsControl) {
			return fmt.Errorf("%w: %s contains control or invalid characters", ErrActingIdentityInvalid, field.name)
		}
	}
	if _, err := ParseRole(string(id.Role)); err != nil {
		return fmt.Errorf("%w: %w", ErrActingIdentityInvalid, err)
	}
	return nil
}

// HeaderValue renders the identity for ActingIdentityHeader: one line of
// JSON restricted to printable ASCII, so every proxy carries it unchanged.
func (id ActingIdentity) HeaderValue() string {
	data, err := json.Marshal(id)
	if err != nil {
		// Unreachable: the struct holds only strings.
		return ""
	}
	var b strings.Builder
	b.Grow(len(data))
	for _, r := range string(data) {
		switch {
		case r < 0x7f:
			// json.Marshal already escaped the control characters.
			b.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// ParseActingIdentity decodes and validates an ActingIdentityHeader value.
// Unknown fields are ignored so a newer service can say more; the display
// name is trimmed and the account is taken exactly as asserted.
func ParseActingIdentity(value string) (ActingIdentity, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return ActingIdentity{}, fmt.Errorf("%w: empty header", ErrActingIdentityInvalid)
	}
	if len(value) > actingIdentityMaxHeader {
		return ActingIdentity{}, fmt.Errorf("%w: header exceeds %d bytes", ErrActingIdentityInvalid, actingIdentityMaxHeader)
	}
	var identity ActingIdentity
	if err := json.Unmarshal([]byte(value), &identity); err != nil {
		return ActingIdentity{}, fmt.Errorf("%w: %w", ErrActingIdentityInvalid, err)
	}
	identity.Name = strings.TrimSpace(identity.Name)
	if err := identity.Validate(); err != nil {
		return ActingIdentity{}, err
	}
	return identity, nil
}
