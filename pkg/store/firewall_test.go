package store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

// This tests the wire contract independently of command validation: opening a
// firewall port must PUT only addPort, preserving unrelated workspace settings.
func TestCloudFirewallMutationWireContract(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		update     CloudFirewallUpdate
	}{
		{name: "add restricted", body: `{"addPort":{"port":"4242","allowedIPs":"user-ip","clientIPs":["203.0.113.7/32"]}}`, update: CloudFirewallUpdate{AddPort: &CreateFirewallRule{Port: "4242", AllowedIPs: "user-ip", ClientIPs: []string{"203.0.113.7/32"}}}},
		{name: "add public", body: `{"addPort":{"port":"4242","allowedIPs":"all"}}`, update: CloudFirewallUpdate{AddPort: &CreateFirewallRule{Port: "4242", AllowedIPs: "all"}}},
		{name: "revoke", body: `{"revokePort":"4242"}`, update: CloudFirewallUpdate{RevokePort: "4242"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := MakeMockAuthHTTPStore()
			httpmock.ActivateNonDefault(s.authHTTPClient.restyClient.GetClient())
			t.Cleanup(httpmock.DeactivateAndReset)
			url := s.authHTTPClient.restyClient.BaseURL + "/api/workspaces/workspace-1"
			httpmock.RegisterResponder(http.MethodPut, url, func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.JSONEq(t, tc.body, string(body))
				require.Equal(t, "application/json", req.Header.Get("Content-Type"))
				return httpmock.NewStringResponse(http.StatusAccepted, ""), nil
			})
			err := s.ModifyCloudFirewall(context.Background(), "workspace-1", &tc.update)
			require.NoError(t, err)
			require.Equal(t, 1, httpmock.GetTotalCallCount())
		})
	}
}

func TestCloudFirewallReadsLiveState(t *testing.T) {
	s := MakeMockAuthHTTPStore()
	httpmock.ActivateNonDefault(s.authHTTPClient.restyClient.GetClient())
	t.Cleanup(httpmock.DeactivateAndReset)
	url := s.authHTTPClient.restyClient.BaseURL + "/api/workspaces/workspace-1"
	body := `{"instanceTypeInfo":{"can_modify_firewall_rules":true},"exposedPorts":[9999],"environment":{"provision":{"Directive":{"CreateInstanceRequest":{"firewall_rules_v2":{"ingress_rules":[{"from_port":8888}]}}}},"instance":{"firewall_rules":{"ingress_rules":[{"id":"sgr-a:sgr-b","from_port":4242,"to_port":4242,"ip_ranges":["203.0.113.7/32"],"labels":{"ip-override":"user-ip"}}],"egress_rules":[{"from_port":7777}]}}}}`
	httpmock.RegisterResponder(http.MethodGet, url, func(_ *http.Request) (*http.Response, error) {
		response := httpmock.NewStringResponse(http.StatusOK, body)
		response.Header.Set("Content-Type", "application/json")
		return response, nil
	})
	live, err := s.GetCloudFirewall(context.Background(), "workspace-1")
	require.NoError(t, err)
	require.True(t, live.InstanceTypeInfo.CanModifyFirewallRules)
	require.Equal(t, []CloudFirewallRule{{ID: "sgr-a:sgr-b", FromPort: 4242, ToPort: 4242, IPRanges: []string{"203.0.113.7/32"}, Labels: map[string]string{"ip-override": "user-ip"}}}, live.Environment.Instance.FirewallRules.IngressRules)
}

func TestCloudFirewallRetriesOnlyExplicitRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		statuses               []int
		transportError, cancel bool
		wantCalls, wantWaits   int
		wantError              bool
	}{
		{name: "rate limit then accepted", statuses: []int{429, 202}, wantCalls: 2, wantWaits: 1},
		{name: "bounded retries", statuses: []int{429, 429, 429, 429}, wantCalls: 4, wantWaits: 3, wantError: true},
		{name: "server error is ambiguous", statuses: []int{500}, wantCalls: 1, wantError: true},
		{name: "transport error is ambiguous", transportError: true, wantCalls: 1, wantError: true},
		{name: "canceled backoff", statuses: []int{429}, cancel: true, wantCalls: 1, wantWaits: 1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := MakeMockAuthHTTPStore()
			httpmock.ActivateNonDefault(s.authHTTPClient.restyClient.GetClient())
			t.Cleanup(httpmock.DeactivateAndReset)
			url := s.authHTTPClient.restyClient.BaseURL + "/api/workspaces/workspace-1"
			calls, waits := 0, 0
			httpmock.RegisterResponder(http.MethodPut, url, func(_ *http.Request) (*http.Response, error) {
				calls++
				if tc.transportError {
					return nil, errors.New("connection lost")
				}
				require.LessOrEqual(t, calls, len(tc.statuses))
				response := httpmock.NewStringResponse(tc.statuses[calls-1], "")
				response.Header.Set("Retry-After", "5")
				return response, nil
			})
			wait := func(_ context.Context, delay time.Duration) error {
				waits++
				require.GreaterOrEqual(t, delay, 5*time.Second)
				if tc.cancel {
					return context.Canceled
				}
				return nil
			}
			err := s.cloudFirewallRequest(context.Background(), http.MethodPut, "workspace-1", &CloudFirewallUpdate{RevokePort: "4242"}, nil, wait)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantCalls, calls)
			require.Equal(t, tc.wantWaits, waits)
		})
	}
}

func TestCloudFirewallBackoff(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{header: "", attempt: 0, want: time.Second},
		{header: "invalid", attempt: 2, want: 4 * time.Second},
		{header: "1", attempt: 2, want: 4 * time.Second},
		{header: "10", attempt: 0, want: 10 * time.Second},
		{header: now.Add(10 * time.Second).Format(http.TimeFormat), want: 10 * time.Second},
	} {
		require.Equal(t, tc.want, firewallRetryDelay(tc.header, tc.attempt, now))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, waitFirewallRetry(ctx, time.Hour), context.Canceled)
}
