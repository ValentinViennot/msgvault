package cmd

import (
	"fmt"

	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/config"
)

// newOIDCProvider builds the identity provider client from [auth.oidc].
// configured is false when no issuer is set; the provider is then nil.
func newOIDCProvider(cfg *config.Config) (provider *oidc.Provider, configured bool, err error) {
	section := cfg.Auth.OIDC
	if !section.Enabled() {
		return nil, false, nil
	}
	provider, err = oidc.New(oidc.Config{
		Issuer:        section.Issuer,
		ClientID:      section.ClientID,
		ClientSecret:  section.ResolveClientSecret(nil),
		PublicURL:     section.PublicURL,
		Resource:      section.Resource,
		Scopes:        section.Scopes,
		GroupsClaim:   section.GroupsClaim,
		AdminGroups:   section.AdminGroups,
		MemberGroups:  section.MemberGroups,
		ViewerGroups:  section.ViewerGroups,
		AllowedEmails: section.AllowedEmails,
		ProviderName:  section.ProviderName,
	})
	if err != nil {
		return nil, true, fmt.Errorf("configure identity provider: %w", err)
	}
	if section.PublicURL != "" && section.ResolveClientSecret(nil) == "" && section.ClientSecretEnv != "" {
		logger.Warn("[auth.oidc] client_secret_env is not set; browser login will fail at the token exchange",
			"variable", section.ClientSecretEnv)
	}
	return provider, true, nil
}
