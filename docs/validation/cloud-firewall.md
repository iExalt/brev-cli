# Cloud Firewall live validation

Tested on 2026-11-01 UTC (2026-10-31 EDT) using a local build of the firewall
feature on top of `adcb15549b84f596244a0f154465511973d39e58`.

Build command: `mise exec -- go build -o /tmp/brev-firewall-live .`

Tested binary SHA-256:
`968e03468c96045edc17225de1361ae0f3ce8ccc307ac6dbda86e2c6bb1df3d3`.
The command documentation was updated after this binary was tested; executable
behavior was unchanged. No installed CLI was replaced.

## Instances and cost limits

The requested limits were compute below $0.35/hour and storage below $0.10/hour.
Prices were checked against Brev's live instance catalog before creation, then
instance type and disk size were checked against the workspace responses.

| Provider | Type | Workspace ID | Actual storage | Compute/hour | Storage/hour |
| --- | --- | --- | --- | --- | --- |
| GCP | `n1-standard-1` | `wx5zr2tjp` | 50 GiB | $0.064196 | at most $0.016578 |
| Nebius | `cpu-e2.2vcpu-8gb` | `ovwpcb0aq` | 50 GiB | $0.072000 | at most $0.009072 |
| Crusoe | `c1a.2x` | `467k01gf2` | 256 GiB | $0.096000 | at most $0.036300 |

Combined compute was $0.232196/hour; the conservative combined storage estimate
was $0.061950/hour. These are catalog rates, not an invoice or an independent
verification of free-tier eligibility.

GCP storage uses the highest listed rate, $0.000307/GB/hour, as a conservative
bound. Nebius storage was $0.000168/GB/hour. Crusoe was $0.000132/GB/hour.
The estimates conservatively convert GiB to decimal GB, rounded up to 54 GB,
54 GB, and 275 GB respectively, to cover the catalog's GB/GiB unit ambiguity.
Crusoe reported 256 GiB after requesting 128 GiB; the estimate includes all of it.
The CLI search display omits the fixed-disk storage rate even though the raw
catalog supplies one, so the raw catalog was used for this check.

## Method

Each temporary VM ran a Python standard-library TCP and UDP echo service under
systemd on `0.0.0.0:42429`. The service was installed explicitly over SSH after
provisioning because the startup-script listener was inactive on the first VM.
Both protocols passed loopback self-tests before public probing.

Public probes ran from the developer machine directly to each VM's public IPv4
address, without port forwarding or SkyBridge. Each probe used a fresh socket
and a random nonce; success required the exact expected response, not merely a
successful TCP handshake or a UDP send. Socket timeout was three seconds.

For GCP and Crusoe:

1. `brev firewall ls <id> --json` showed only the pre-existing SSH rule.
2. Two fresh TCP/UDP probe pairs timed out before adding a rule.
3. `brev firewall add <id> 42429 --allow <probe-ip>/32 --json` succeeded.
4. Polling `firewall ls` confirmed the live ingress rule and source restriction.
5. TCP and UDP returned the expected nonce response.
6. `brev firewall rm <id> 42429 --json` succeeded; polling confirmed rule removal.
7. Three fresh TCP/UDP probe pairs timed out after removal.
8. Both loopback self-tests still passed, demonstrating that the listener had
   remained healthy. The SSH rule remained present throughout.

The tests used the CLI's default `brevapi` endpoint without a `BREV_API_URL`
override. The same nested live-rule schema worked on GCP and Crusoe.

## Results and receipts

| Provider | Before add | After add | After removal | Result |
| --- | --- | --- | --- | --- |
| GCP | TCP/UDP blocked | TCP/UDP exact echo | TCP/UDP blocked, 3 samples | Pass |
| Crusoe | TCP/UDP blocked | TCP/UDP exact echo | TCP/UDP blocked, 3 samples | Pass after retry |
| Nebius | TCP/UDP blocked; loopback healthy | Mutation refused | Mutation refused | Unsupported |

GCP's successful public probe at 00:48:52 UTC (20:48:52 EDT the previous day)
returned TCP in 0.145 seconds and UDP in 0.281 seconds. Crusoe's successful probe
at 00:50:19 UTC (20:50:19 EDT the previous day) returned TCP in 0.277 seconds and
UDP in 0.345 seconds.

Representative command output:

```text
active
tcp listener self-test PASS
udp listener self-test PASS

{"port":"42429","allowedIPs":"user-ip","clientIPs":["<probe-ip>/32"]}
Removing ALL 1 Cloud Firewall rule(s) on port 42429, regardless of source addresses.
{"revokePort":"42429"}
```

All affordable Nebius CPU offerings in the catalog reported no Flex Ports
support. The created instance likewise did not report
`can_modify_firewall_rules: true`, and its live firewall object was empty. Both
add and remove returned:

```text
this instance does not report Flex Ports support (can_modify_firewall_rules); refusing to change its firewall
```

Nebius therefore could not satisfy the requested reachable-after-add test.
The capability guard was preserved; no raw mutation bypass was attempted.

Crusoe's first remove attempt returned `resource exhausted` during workspace
lookup, before the firewall mutation. After backing off, the same CLI command
succeeded and all post-removal probes failed as expected. Inventory/lookup rate
limits also affected a status poll and the first Nebius remove check. These occur
outside the firewall HTTP request's bounded 429 retry path.

## Cleanup

Deletion was restricted to the three immutable workspace IDs above. All three
were absent from inventory at the final verification on 2026-11-01 01:06:28 UTC
(2026-10-31 21:06:28 EDT). Nebius took longer to terminate than the other providers.
All 20 pre-existing IDs remained present with unchanged status.

```json
{"remaining_targets":[],"protected_retained":20,"protected_count":20,"protected_state_changes":[]}
```

## Limits

This validates one CPU type and one restricted-source rule per supported
provider. It does not establish behavior for every region, GPU type, port range,
or provider; ranges and atomic replacement remain unsupported by the CLI.
No AWS instance was created in this run.
