package store

import (
	"context"
	"net/http"
	"strconv"
	"time"

	breverrors "github.com/brevdev/brev-cli/pkg/errors"
)

// CloudFirewallWorkspace reads only the live provider firewall, not exposedPorts
// or the creation directive, which may be stale.
type CloudFirewallWorkspace struct {
	InstanceTypeInfo *struct {
		CanModifyFirewallRules bool `json:"can_modify_firewall_rules"`
	} `json:"instanceTypeInfo"`
	Environment *struct {
		Instance *struct {
			FirewallRules *CloudFirewallRules `json:"firewall_rules"`
		} `json:"instance"`
	} `json:"environment"`
}

// CloudFirewallRules contains the live ingress rules returned by the provider.
type CloudFirewallRules struct {
	IngressRules []CloudFirewallRule `json:"ingress_rules"`
}

// CloudFirewallRule preserves the provider ID, including colon-joined IDs.
// The API does not report a protocol for these rules.
type CloudFirewallRule struct {
	ID       string            `json:"id"`
	FromPort int               `json:"from_port"`
	ToPort   int               `json:"to_port"`
	IPRanges []string          `json:"ip_ranges"`
	Labels   map[string]string `json:"labels"`
}

// CloudFirewallUpdate changes a port on an existing workspace. RevokePort removes
// every ingress rule for that port, not an individual provider rule ID.
type CloudFirewallUpdate struct {
	AddPort    *CreateFirewallRule `json:"addPort,omitempty"`
	RevokePort string              `json:"revokePort,omitempty"`
}

func (s AuthHTTPStore) GetCloudFirewall(ctx context.Context, workspaceID string) (*CloudFirewallWorkspace, error) {
	var result CloudFirewallWorkspace
	err := s.cloudFirewallRequest(ctx, http.MethodGet, workspaceID, nil, &result, waitFirewallRetry)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ModifyCloudFirewall accepts asynchronous 202 responses without requiring a
// workspace response body. The caller must GET to observe the applied state.
func (s AuthHTTPStore) ModifyCloudFirewall(ctx context.Context, workspaceID string, update *CloudFirewallUpdate) error {
	return s.cloudFirewallRequest(ctx, http.MethodPut, workspaceID, update, nil, waitFirewallRetry)
}

func (s AuthHTTPStore) cloudFirewallRequest(
	ctx context.Context, method, workspaceID string, body, result interface{},
	wait func(context.Context, time.Duration) error,
) error {
	for attempt := 0; ; attempt++ {
		request := s.authHTTPClient.restyClient.R().SetContext(ctx).
			SetHeader("Content-Type", "application/json").
			SetPathParam(workspaceIDParamName, workspaceID)
		if body != nil {
			request.SetBody(body)
		}
		if result != nil {
			request.SetResult(result)
		}
		response, err := request.Execute(method, workspacePath)
		if err != nil {
			// An ambiguous transport failure may have applied an add. Never replay it.
			return breverrors.WrapAndTrace(err)
		}
		if response.StatusCode() == http.StatusTooManyRequests && attempt < 3 {
			delay := firewallRetryDelay(response.Header().Get("Retry-After"), attempt, time.Now())
			if err := wait(ctx, delay); err != nil {
				return breverrors.WrapAndTrace(err)
			}
			continue
		}
		if response.IsError() {
			return NewHTTPResponseError(response)
		}
		return nil
	}
}

func firewallRetryDelay(retryAfter string, attempt int, now time.Time) time.Duration {
	delay := time.Second << attempt
	if seconds, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && seconds >= 0 {
		// Avoid overflowing a duration for an invalidly large header.
		if seconds <= int64((1<<63-1)/time.Second) {
			if minimum := time.Duration(seconds) * time.Second; minimum > delay {
				delay = minimum
			}
		}
	} else if deadline, err := http.ParseTime(retryAfter); err == nil && deadline.Sub(now) > delay {
		delay = deadline.Sub(now)
	}
	return delay
}

func waitFirewallRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return breverrors.WrapAndTrace(ctx.Err())
	case <-timer.C:
		return nil
	}
}
