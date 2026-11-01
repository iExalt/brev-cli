// Package firewall manages cloud-provider firewall rules for existing instances.
package firewall

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/brevdev/brev-cli/pkg/cmd/cmderrors"
	"github.com/brevdev/brev-cli/pkg/cmd/util"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/store"
	"github.com/spf13/cobra"
)

//go:embed doc.md
var doc string

// Store resolves instances in the active organization and updates their firewall.
type Store interface {
	util.GetWorkspaceByNameOrIDErrStore
	GetCloudFirewall(context.Context, string) (*store.CloudFirewallWorkspace, error)
	ModifyCloudFirewall(context.Context, string, *store.CloudFirewallUpdate) error
}

// NewCmdFirewall creates the Cloud Firewall Ports command group.
func NewCmdFirewall(s Store) *cobra.Command {
	cmd := &cobra.Command{
		Use: "firewall", Short: "Manage Cloud Firewall ports for instances",
		Long: doc, Annotations: map[string]string{"networking": ""},
		Args: cmderrors.TransformToValidationError(cobra.NoArgs),
	}
	cmd.AddCommand(newListCommand(s), newOpenCommand(s), newRemoveCommand(s))
	return cmd
}

func newOpenCommand(s Store) *cobra.Command {
	var allowed []string
	var anywhere, jsonOutput bool
	cmd := &cobra.Command{
		Annotations: map[string]string{"networking": ""},
		Use:         "add <instance> <port>", Aliases: []string{"open"},
		Short:   "Open a Cloud Firewall port to explicit source CIDRs or all IPs",
		Example: "  brev firewall open my-instance 4242 --allow 203.0.113.7/32\n  brev firewall open my-instance 8080 --allow-anywhere",
		Args:    cmderrors.TransformToValidationError(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule, err := makeRule(args[1], allowed, anywhere)
			if err != nil {
				return err
			}
			id, rules, err := liveRules(cmd.Context(), s, args[0], true)
			if err != nil {
				return breverrors.WrapAndTrace(err)
			}
			n, _ := strconv.Atoi(rule.Port) // makeRule validated and normalized the port.
			for _, existing := range rules {
				if coversPort(existing, n) {
					return breverrors.NewValidationError("a firewall rule already covers this port; use firewall ls to inspect it, then rm and wait for removal before adding the complete source list")
				}
			}
			if err := s.ModifyCloudFirewall(cmd.Context(), id, &store.CloudFirewallUpdate{AddPort: rule}); err != nil {
				return breverrors.WrapAndTrace(err)
			}
			if jsonOutput {
				return breverrors.WrapAndTrace(json.NewEncoder(cmd.OutOrStdout()).Encode(rule))
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Requested Cloud Firewall port %s on %s; the change applies asynchronously. Check with 'brev firewall ls %s'.\n", rule.Port, args[0], args[0])
			return breverrors.WrapAndTrace(err)
		},
	}
	cmd.Flags().StringArrayVar(&allowed, "allow", nil, "Allow a source CIDR (repeatable)")
	cmd.Flags().BoolVar(&anywhere, "allow-anywhere", false, "Allow access from all IPs")
	cmd.Flags().BoolVar(&anywhere, "all", false, "Allow access from all IPs (alias for --allow-anywhere)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output the submitted rule as JSON")
	cmd.MarkFlagsMutuallyExclusive("allow", "allow-anywhere", "all")
	cmd.MarkFlagsOneRequired("allow", "allow-anywhere", "all")
	return cmd
}

func makeRule(port string, allowed []string, anywhere bool) (*store.CreateFirewallRule, error) {
	n, err := mutablePort(port)
	if err != nil {
		return nil, err
	}
	if anywhere == (len(allowed) > 0) {
		return nil, breverrors.NewValidationError("specify either --allow <CIDR> or --allow-anywhere")
	}
	rule := &store.CreateFirewallRule{Port: strconv.Itoa(n), AllowedIPs: "all"}
	if !anywhere {
		rule.AllowedIPs = "user-ip"
		for _, source := range allowed {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return nil, breverrors.NewValidationError(fmt.Sprintf("invalid source CIDR %q", source))
			}
			rule.ClientIPs = append(rule.ClientIPs, prefix.Masked().String())
		}
	}
	return rule, nil
}

func mutablePort(port string) (int, error) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, breverrors.NewValidationError("port must be an integer between 1 and 65535; ranges are not supported")
	}
	if n == 22 {
		return 0, breverrors.NewValidationError("port 22 is reserved for Brev SSH access and cannot be changed by this command")
	}
	return n, nil
}

func coversPort(rule store.CloudFirewallRule, port int) bool {
	return rule.FromPort <= port && rule.ToPort >= port
}

func liveRules(ctx context.Context, s Store, name string, mutate bool) (string, []store.CloudFirewallRule, error) {
	workspace, err := util.GetAnyWorkspaceByIDOrNameInActiveOrgErr(s, name)
	if err != nil {
		return "", nil, breverrors.WrapAndTrace(err)
	}
	live, err := s.GetCloudFirewall(ctx, workspace.ID)
	if err != nil {
		return "", nil, breverrors.WrapAndTrace(err)
	}
	if live == nil {
		return "", nil, breverrors.NewValidationError("the API returned no workspace firewall data")
	}
	if mutate && (live.InstanceTypeInfo == nil || !live.InstanceTypeInfo.CanModifyFirewallRules) {
		return "", nil, breverrors.NewValidationError("this instance does not report Flex Ports support (can_modify_firewall_rules); refusing to change its firewall")
	}
	if live.Environment == nil || live.Environment.Instance == nil || live.Environment.Instance.FirewallRules == nil ||
		live.Environment.Instance.FirewallRules.IngressRules == nil {
		return "", nil, breverrors.NewValidationError("live Cloud Firewall ingress rules are unavailable; inspect the instance in the Brev console")
	}
	rules := live.Environment.Instance.FirewallRules.IngressRules
	for _, rule := range rules {
		if rule.FromPort < 1 || rule.ToPort > 65535 || rule.FromPort > rule.ToPort {
			return "", nil, breverrors.NewValidationError("the API returned an unsupported firewall port range; inspect the instance in the Brev console")
		}
	}
	return workspace.ID, rules, nil
}

func newListCommand(s Store) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use: "ls <instance>", Aliases: []string{"list"},
		Annotations: map[string]string{"networking": ""},
		Short:       "List live Cloud Firewall ingress rules",
		Args:        cmderrors.TransformToValidationError(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, rules, err := liveRules(cmd.Context(), s, args[0], false)
			if err != nil {
				return err
			}
			if jsonOutput {
				return breverrors.WrapAndTrace(json.NewEncoder(cmd.OutOrStdout()).Encode(rules))
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(w, "PORTS\tPROTOCOL\tSOURCES\tRULE ID"); err != nil {
				return breverrors.WrapAndTrace(err)
			}
			for _, rule := range rules {
				ports := strconv.Itoa(rule.FromPort)
				if rule.FromPort != rule.ToPort {
					ports += "-" + strconv.Itoa(rule.ToPort)
				}
				if _, err := fmt.Fprintf(w, "%s\tTCP/UDP\t%s\t%s\n", ports, strings.Join(rule.IPRanges, ", "), rule.ID); err != nil {
					return breverrors.WrapAndTrace(err)
				}
			}
			return breverrors.WrapAndTrace(w.Flush())
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output live ingress rules as JSON")
	return cmd
}

func newRemoveCommand(s Store) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use: "rm <instance> <port>", Aliases: []string{"remove", "close"},
		Annotations: map[string]string{"networking": ""},
		Short:       "Remove ALL Cloud Firewall rules on a port",
		Long:        "Remove every Cloud Firewall rule on a single port, regardless of its source addresses. Port 22 and rules spanning port ranges cannot be removed by this command.",
		Args:        cmderrors.TransformToValidationError(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := mutablePort(args[1])
			if err != nil {
				return err
			}
			id, rules, err := liveRules(cmd.Context(), s, args[0], true)
			if err != nil {
				return err
			}
			count := 0
			for _, rule := range rules {
				if !coversPort(rule, port) {
					continue
				}
				if rule.FromPort != rule.ToPort {
					return breverrors.NewValidationError("this port is covered by a range rule; range revocation is not supported")
				}
				count++
			}
			if count == 0 {
				return breverrors.NewValidationError("no live Cloud Firewall rules found for this port")
			}
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Removing ALL %d Cloud Firewall rule(s) on port %d, regardless of source addresses.\n", count, port); err != nil {
				return breverrors.WrapAndTrace(err)
			}
			update := &store.CloudFirewallUpdate{RevokePort: strconv.Itoa(port)}
			if err := s.ModifyCloudFirewall(cmd.Context(), id, update); err != nil {
				return breverrors.WrapAndTrace(err)
			}
			if jsonOutput {
				return breverrors.WrapAndTrace(json.NewEncoder(cmd.OutOrStdout()).Encode(update))
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removal requested; the change applies asynchronously. Check with 'brev firewall ls %s'.\n", args[0])
			return breverrors.WrapAndTrace(err)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output the submitted revokePort request as JSON")
	return cmd
}
