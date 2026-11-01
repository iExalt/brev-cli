Manage the Cloud Firewall Ports shown in the Brev console for an existing instance.

List the live ingress rules, including provider rule IDs and source networks:

    brev firewall ls my-instance
    brev firewall ls my-instance --json

Open a port to one or more source networks:

    brev firewall add my-instance 4242 --allow 203.0.113.7/32
    brev firewall add my-instance 4242 --allow 203.0.113.0/24 --allow 198.51.100.4/32

Open a port to all IPs explicitly:

    brev firewall add my-instance 8080 --all

Remove every rule on a port, regardless of the addresses each rule allows:

    brev firewall rm my-instance 4242

Aliases: open for add; remove or close for rm; list for ls; --allow-anywhere for --all.

Instances are resolved by name or ID within the active organization, or the
organization selected by the global --org flag. Mutations require the instance to
report Flex Ports support (can_modify_firewall_rules). Missing live firewall data
is an error, not an empty list. The API enforces permissions and provider support.

Requests use the CLI's configured API URL and authentication. The console request
was captured against brevapi2; the CLI normally defaults to brevapi. To select
the captured endpoint explicitly:

    BREV_API_URL=https://brevapi2.us-west-2-prod.control-plane.brev.dev brev firewall ls my-instance

Port 22 is protected for Brev SSH access. Add and remove accept only single ports
from 1 to 65535. Existing ranges are displayed, but cannot be revoked here.

Add refuses a port covered by an existing rule, including a range. To change its
source networks, remove the port, use ls until the rules disappear, then add one
rule with the complete source list. This causes an interruption; there is no
atomic replace operation. Removal always affects ALL rules on the selected port.
The duplicate check reads live state but cannot prevent races with concurrent
clients or changes still being applied. Serialize changes and wait for ls to
reflect each one before submitting another.

Successful mutations mean the API accepted the request (including HTTP 202).
Changes apply asynchronously; use ls to observe them. Success does not verify
service reachability. Explicit HTTP 429 responses are retried up to three times
with exponential backoff, honoring Retry-After. Transport failures and HTTP 5xx
responses are not replayed because an add may already have taken effect.

With --json, ls prints the live ingress-rule array (id, from_port, to_port,
ip_ranges, labels), preserving colon-joined IDs. Add prints the submitted rule
(port, allowedIPs, optional clientIPs); rm prints the submitted revokePort object.
Removal warnings go to stderr. The restricted-source API mode is named "user-ip";
--allow supplies its clientIPs explicitly without automatic IP discovery.

The table labels protocols TCP/UDP, matching the Cloud Firewall interface. The API
does not return a protocol field. Live tests on GCP and Crusoe verified both TCP
and UDP blocked before adding a rule, reachable after adding it, and blocked after
removing it while the listeners remained healthy. Nebius CPU instances reported
no Flex Ports support and refused mutations. See the repository's
docs/validation/cloud-firewall.md for the test configuration and limits.

Cloud Firewall rules control access to the instance at its cloud provider.
Use brev ports for Brev-managed network mappings and HTTP endpoints, or
brev port-forward for a local SSH tunnel.
