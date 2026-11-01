package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/brevdev/brev-cli/pkg/entity"
	"github.com/brevdev/brev-cli/pkg/store"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	Store
	workspaces []entity.Workspace
	lookupErr  error
	modifyErr  error
	gotID      string
	gotRequest *store.CloudFirewallUpdate
	live       *store.CloudFirewallWorkspace
	liveErr    error
}

func (s *fakeStore) GetActiveOrganizationOrDefault() (*entity.Organization, error) {
	return &entity.Organization{ID: "org-1"}, nil
}

func (s *fakeStore) GetWorkspaceByNameOrID(_, _ string) ([]entity.Workspace, error) {
	return s.workspaces, s.lookupErr
}

func (s *fakeStore) GetCloudFirewall(_ context.Context, _ string) (*store.CloudFirewallWorkspace, error) {
	return s.live, s.liveErr
}

func (s *fakeStore) ModifyCloudFirewall(_ context.Context, id string, request *store.CloudFirewallUpdate) error {
	s.gotID, s.gotRequest = id, request
	return s.modifyErr
}

func liveFixture(t *testing.T, rules string) *store.CloudFirewallWorkspace {
	t.Helper()
	var live store.CloudFirewallWorkspace
	require.NoError(t, json.Unmarshal([]byte(`{"instanceTypeInfo":{"can_modify_firewall_rules":true},"environment":{"instance":{"firewall_rules":{"ingress_rules":`+rules+`}}}}`), &live))
	return &live
}

func TestOpen(t *testing.T) {
	s := &fakeStore{workspaces: []entity.Workspace{{ID: "workspace-1", Name: "example"}}, live: liveFixture(t, `[]`)}
	cmd := NewCmdFirewall(s)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"open", "example", "4242", "--allow", "203.0.113.7/32", "--json"})
	require.NoError(t, cmd.Execute())
	require.Equal(t, "workspace-1", s.gotID)
	require.Equal(t, &store.CloudFirewallUpdate{AddPort: &store.CreateFirewallRule{
		Port: "4242", AllowedIPs: "user-ip", ClientIPs: []string{"203.0.113.7/32"},
	}}, s.gotRequest)
	require.JSONEq(t, `{"port":"4242","allowedIPs":"user-ip","clientIPs":["203.0.113.7/32"]}`, out.String())
}

func TestRuleValidation(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		allowed    []string
		anywhere   bool
		want       *store.CreateFirewallRule
	}{
		{name: "all", port: "8080", anywhere: true, want: &store.CreateFirewallRule{Port: "8080", AllowedIPs: "all"}},
		{name: "networks", port: "0042", allowed: []string{"203.0.113.7/24", "2001:db8::1/128"}, want: &store.CreateFirewallRule{Port: "42", AllowedIPs: "user-ip", ClientIPs: []string{"203.0.113.0/24", "2001:db8::1/128"}}},
		{name: "zero", port: "0", anywhere: true},
		{name: "negative", port: "-1", anywhere: true},
		{name: "too large", port: "65536", anywhere: true},
		{name: "range", port: "80-90", anywhere: true},
		{name: "protected SSH", port: "22", anywhere: true},
		{name: "no access choice", port: "80"},
		{name: "conflicting choice", port: "80", anywhere: true, allowed: []string{"203.0.113.7/32"}},
		{name: "invalid CIDR", port: "80", allowed: []string{"203.0.113.7/33"}},
		{name: "empty CIDR", port: "80", allowed: []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := makeRule(tc.port, tc.allowed, tc.anywhere)
			if tc.want == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, rule)
		})
	}
}

func TestOpenFailuresDoNotReportSuccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		store fakeStore
	}{
		{name: "missing access", args: []string{"open", "example", "80"}},
		{name: "invalid port", args: []string{"open", "example", "bad", "--allow-anywhere"}},
		{name: "missing workspace", args: []string{"open", "example", "80", "--allow-anywhere"}},
		{name: "lookup error", args: []string{"open", "example", "80", "--allow-anywhere"}, store: fakeStore{lookupErr: errors.New("lookup failed")}},
		{name: "ambiguous workspace", args: []string{"open", "example", "80", "--allow-anywhere"}, store: fakeStore{workspaces: []entity.Workspace{{ID: "a"}, {ID: "b"}}}},
		{name: "mutation error", args: []string{"open", "example", "80", "--allow-anywhere"}, store: fakeStore{workspaces: []entity.Workspace{{ID: "a"}}, modifyErr: errors.New("forbidden")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.store.live = liveFixture(t, `[]`)
			cmd := NewCmdFirewall(&tc.store)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(tc.args)
			require.Error(t, cmd.Execute())
			require.Empty(t, out.String())
			if tc.store.modifyErr == nil {
				require.Nil(t, tc.store.gotRequest)
			}
		})
	}
}

func TestFirewallMutationGuards(t *testing.T) {
	for _, tc := range []struct {
		name, command, port, rules string
		unsupported, missing       bool
		want                       string
	}{
		{name: "duplicate", command: "add", port: "80", rules: `[{"from_port":80,"to_port":80}]`, want: "already covers"},
		{name: "overlap", command: "add", port: "80", rules: `[{"from_port":1,"to_port":100}]`, want: "already covers"},
		{name: "unsupported add", command: "add", port: "80", rules: `[]`, unsupported: true, want: "Flex Ports"},
		{name: "unsupported remove", command: "rm", port: "80", rules: `[]`, unsupported: true, want: "Flex Ports"},
		{name: "unknown live state", command: "add", port: "80", rules: `[]`, missing: true, want: "unavailable"},
		{name: "null live rules", command: "add", port: "80", rules: `null`, want: "unavailable"},
		{name: "range removal", command: "rm", port: "80", rules: `[{"from_port":80,"to_port":90}]`, want: "range revocation"},
		{name: "absent removal", command: "rm", port: "80", rules: `[]`, want: "no live"},
		{name: "SSH removal", command: "rm", port: "22", rules: `[{"from_port":22,"to_port":22}]`, want: "reserved"},
		{name: "malformed range", command: "add", port: "80", rules: `[{"from_port":100,"to_port":1}]`, want: "unsupported firewall port range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeStore{workspaces: []entity.Workspace{{ID: "workspace-1"}}, live: liveFixture(t, tc.rules)}
			if tc.unsupported {
				s.live.InstanceTypeInfo.CanModifyFirewallRules = false
			}
			if tc.missing {
				s.live.Environment = nil
			}
			cmd := NewCmdFirewall(s)
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			args := []string{tc.command, "example", tc.port}
			if tc.command == "add" {
				args = append(args, "--all")
			}
			cmd.SetArgs(args)
			require.ErrorContains(t, cmd.Execute(), tc.want)
			require.Nil(t, s.gotRequest)
		})
	}
}

func TestRemoveRevokesWholePort(t *testing.T) {
	s := &fakeStore{workspaces: []entity.Workspace{{ID: "workspace-1"}}, live: liveFixture(t,
		`[{"id":"sgr-a:sgr-b","from_port":4242,"to_port":4242,"ip_ranges":["203.0.113.1/32"]},{"id":"sgr-c","from_port":4242,"to_port":4242,"ip_ranges":["203.0.113.2/32"]}]`)}
	cmd := NewCmdFirewall(s)
	var out, warning bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&warning)
	cmd.SetArgs([]string{"rm", "example", "4242", "--json"})
	require.NoError(t, cmd.Execute())
	require.Equal(t, "workspace-1", s.gotID)
	require.Equal(t, &store.CloudFirewallUpdate{RevokePort: "4242"}, s.gotRequest)
	require.JSONEq(t, `{"revokePort":"4242"}`, out.String())
	require.Contains(t, warning.String(), "ALL 2")
}

func TestListLiveRules(t *testing.T) {
	rules := `[{"id":"sgr-a:sgr-b","from_port":2000,"to_port":2020,"ip_ranges":["203.0.113.1/32"],"labels":{"ip-override":"user-ip"}}]`
	for _, asJSON := range []bool{false, true} {
		s := &fakeStore{workspaces: []entity.Workspace{{ID: "workspace-1"}}, live: liveFixture(t, rules)}
		cmd := NewCmdFirewall(s)
		var out bytes.Buffer
		cmd.SetOut(&out)
		args := []string{"ls", "example"}
		if asJSON {
			args = append(args, "--json")
		}
		cmd.SetArgs(args)
		require.NoError(t, cmd.Execute())
		if asJSON {
			require.JSONEq(t, rules, out.String())
		} else {
			require.Contains(t, out.String(), "TCP/UDP")
			require.Contains(t, out.String(), "2000-2020")
			require.Contains(t, out.String(), "sgr-a:sgr-b")
			require.Contains(t, out.String(), "203.0.113.1/32")
		}
		require.Nil(t, s.gotRequest)
	}
}
