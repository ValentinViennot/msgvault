package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.kenn.io/msgvault/internal/daemonclient"
)

var (
	userListJSON   bool
	userSourcesSet string
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users and the sources they may read",
	Long: `Manage the people who use this archive.

Users are created when someone signs in through the configured identity
provider. Administrators see every source; everyone else sees only the
sources bound to them with 'user sources'. Source IDs come from
'msgvault list-accounts'.

Uses the configured remote server or the local daemon by default.`,
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users, their role, standing, and visible sources",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, _, err := OpenHTTPStore(cmd.Context())
		if err != nil {
			return fmt.Errorf("open daemon: %w", err)
		}
		defer func() { _ = client.Close() }()
		users, err := client.ListUsers(cmd.Context())
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}
		if userListJSON {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(users)
		}
		if len(users) == 0 {
			fmt.Println("No users yet. A user is created on first sign-in through the identity provider.")
			return nil
		}
		writer := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		_, _ = fmt.Fprintln(writer, "ID\tEMAIL\tNAME\tROLE\tSTANDING\tSOURCES")
		for _, user := range users {
			standing := "active"
			if user.Disabled {
				standing = "disabled"
			}
			sources := "all"
			if user.Role != "admin" {
				sources = formatSourceIDs(user.SourceIDs)
			}
			_, _ = fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t%s\n", user.ID, user.Email, user.DisplayName, user.Role, standing, sources)
		}
		return writer.Flush()
	},
}

var userSourcesCmd = &cobra.Command{
	Use:   "sources <email>",
	Short: "Show or replace the sources a user may read",
	Long: `Show the sources bound to a user, or replace them with --set.

Examples:
	msgvault user sources alice@example.com
	msgvault user sources alice@example.com --set 1,3
	msgvault user sources alice@example.com --set none`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, _, err := OpenHTTPStore(cmd.Context())
		if err != nil {
			return fmt.Errorf("open daemon: %w", err)
		}
		defer func() { _ = client.Close() }()
		user, err := findUser(cmd.Context(), client, args[0])
		if err != nil {
			return err
		}
		if !cmd.Flags().Changed("set") {
			fmt.Printf("%s sees: %s\n", user.Email, formatSourceIDs(user.SourceIDs))
			return nil
		}
		ids, err := parseSourceIDs(userSourcesSet)
		if err != nil {
			return usageErr(cmd, err)
		}
		updated, err := client.SetUserSources(cmd.Context(), user.ID, ids)
		if err != nil {
			return fmt.Errorf("set sources: %w", err)
		}
		fmt.Printf("%s now sees: %s\n", updated.Email, formatSourceIDs(updated.SourceIDs))
		return nil
	},
}

var userDisableCmd = &cobra.Command{
	Use:   "disable <email>",
	Short: "Block a user from signing in",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return setUserStanding(cmd, args[0], true) },
}

var userEnableCmd = &cobra.Command{
	Use:   "enable <email>",
	Short: "Restore a disabled user",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return setUserStanding(cmd, args[0], false) },
}

func setUserStanding(cmd *cobra.Command, email string, disabled bool) error {
	client, _, err := OpenHTTPStore(cmd.Context())
	if err != nil {
		return fmt.Errorf("open daemon: %w", err)
	}
	defer func() { _ = client.Close() }()
	user, err := findUser(cmd.Context(), client, email)
	if err != nil {
		return err
	}
	updated, err := client.SetUserDisabled(cmd.Context(), user.ID, disabled)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if updated.Disabled {
		fmt.Printf("%s is disabled\n", updated.Email)
	} else {
		fmt.Printf("%s is active\n", updated.Email)
	}
	return nil
}

var errUserNotFound = errors.New("user not found")

func findUser(ctx context.Context, client *daemonclient.Client, email string) (*daemonclient.User, error) {
	users, err := client.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	wanted := strings.ToLower(strings.TrimSpace(email))
	for i := range users {
		if strings.ToLower(users[i].Email) == wanted {
			return &users[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s (a user is created on first sign-in)", errUserNotFound, email)
}

// parseSourceIDs reads "1,3" or "none".
func parseSourceIDs(value string) ([]int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return []int64{}, nil
	}
	var ids []int64
	for entry := range strings.SplitSeq(trimmed, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, err := strconv.ParseInt(entry, 10, 64)
		if err != nil || id < 1 {
			return nil, fmt.Errorf("--set expects comma-separated positive source IDs or \"none\", got %q", entry)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func formatSourceIDs(ids []int64) string {
	if len(ids) == 0 {
		return "none"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}

func init() {
	userListCmd.Flags().BoolVar(&userListJSON, "json", false, "Output as JSON")
	userSourcesCmd.Flags().StringVar(&userSourcesSet, "set", "", "Replace the bound sources: comma-separated source IDs, or \"none\"")
	userCmd.AddCommand(userListCmd, userSourcesCmd, userDisableCmd, userEnableCmd)
	rootCmd.AddCommand(userCmd)
}
