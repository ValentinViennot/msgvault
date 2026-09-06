package api

import (
	"crypto/sha256"
	"crypto/subtle"

	"go.kenn.io/msgvault/internal/authz"
)

// namedAPIKey is one resolved [[auth.api_keys]] credential. Only the digest
// is kept so a memory dump of the daemon does not hand out the secrets.
type namedAPIKey struct {
	name       string
	digest     [sha256.Size]byte
	role       authz.Role
	user       string
	onBehalfOf bool
}

// loadNamedAPIKeys resolves the configured named keys once at construction.
// A key that collides with [server].api_key or with an earlier named key is
// dropped with a warning: two principals for one secret would be ambiguous.
func (s *Server) loadNamedAPIKeys() {
	if s.cfg == nil {
		return
	}
	resolved, warnings := s.cfg.Auth.ResolveAPIKeys(nil)
	for _, warning := range warnings {
		s.warn(warning)
	}
	serverDigest := sha256.Sum256([]byte(s.cfg.Server.APIKey))
	keys := make([]namedAPIKey, 0, len(resolved))
	for _, key := range resolved {
		digest := sha256.Sum256([]byte(key.Key))
		if s.cfg.Server.APIKey != "" && digest == serverDigest {
			s.warn("[[auth.api_keys]] " + key.Name + ": same value as [server].api_key; the named key is ignored")
			continue
		}
		duplicate := false
		for _, earlier := range keys {
			if earlier.digest == digest {
				s.warn("[[auth.api_keys]] " + key.Name + ": same value as " + earlier.name + "; the later key is ignored")
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		keys = append(keys, namedAPIKey{name: key.Name, digest: digest, role: key.Role, user: key.User, onBehalfOf: key.OnBehalfOf})
	}
	s.namedKeys = keys
}

func (s *Server) warn(message string) {
	if s.logger != nil {
		s.logger.Warn(message)
	}
}

// principalForAPIKey resolves a bearer credential. [server].api_key is the
// administrator; named keys carry their configured role. Every comparison is
// constant-time.
func (s *Server) principalForAPIKey(credential string) (authz.Principal, bool) {
	principal, _, ok := s.keyPrincipal(credential)
	return principal, ok
}

// keyPrincipal resolves a bearer credential and reports whether the key may
// act on behalf of a user.
func (s *Server) keyPrincipal(credential string) (authz.Principal, bool, bool) {
	if credential == "" {
		return authz.Principal{}, false, false
	}
	if s.cfg.Server.APIKey != "" && constantTimeAPIKeyEqual(credential, s.cfg.Server.APIKey) {
		return authz.ServerKey(), false, true
	}
	supplied := sha256.Sum256([]byte(credential))
	for _, key := range s.namedKeys {
		if subtle.ConstantTimeCompare(key.digest[:], supplied[:]) == 1 {
			return authz.Principal{Kind: authz.PrincipalAPIKey, Name: key.name, Role: key.role, Email: key.user}, key.onBehalfOf, true
		}
	}
	return authz.Principal{}, false, false
}
