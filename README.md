# Tailscale Proxy

**One VPS. A separate selectable Tailscale exit node for each proxy.**

Adapted from [wireguard-ikev2-proxy](https://github.com/waqaarhussain/wireguard-ikev2-proxy) and the proxy model in [stash-ikev2-proxy](https://github.com/waqaarhussain/stash-ikev2-proxy). The standalone WireGuard server, IKEv2 server, Stash profiles, certificate profiles and profile download servers are removed.

Each country runs one systemd service with its own persistent Tailscale identity. It uses sing-box's built-in Tailscale endpoint, so Docker, a separate tailscaled daemon and host VPN routing rules are unnecessary. Devices use the normal Tailscale app, including on Apple TV.

| Selected exit node | Connection |
| --- | --- |
| `uk` | Your UK upstream proxy |
| `usa` | Your USA upstream proxy |
| `turkey` | Your Turkey upstream proxy |

Apple TV can select USA while an iPhone selects Turkey, using the same VPS simultaneously. The upstream proxy determines the public exit IP and country.

## Install

Use an Ubuntu/Debian VPS with systemd, AMD64 or ARM64, internet access and permission to run background services. A fresh VPS is recommended. The installer does not remove or convert an existing Stash/WireGuard installation. Existing generic helper commands are not overwritten; use `tailscale-proxy add` etc. if these names already belong to another tool.

```bash
curl -fsSL https://raw.githubusercontent.com/waqaarhussain/tailscale-proxy/main/install.sh -o /tmp/tailscale-proxy-install.sh && sudo bash /tmp/tailscale-proxy-install.sh
```

The installer installs a checksummed, pinned sing-box **1.14.4** release with Tailscale support. It offers to add the first proxy immediately. Each later `add` creates another country exit on the same VPS. The exit node uses the proxy name as its hostname, without an added `proxy-` prefix. Hostnames are lowercase with spaces/punctuation converted to hyphens, for example **USA Residential** becomes `usa-residential`. Duplicate labels get a numeric suffix. Rerunning the installer keeps the registry and Tailscale identities and restarts the existing exits. Original generated names such as `proxy-usa` are migrated to `usa`; the node state directory, ports, proxy credentials and direct-IP bypass are preserved. To update without adding a new exit, pass `--no-add` to the installer.

## Add and connect

1. Run `sudo add` (or `sudo tailscale-proxy add`). Enter a country name, proxy type, host, port and credentials. HTTP, SOCKS5 and Shadowsocks are supported. Passwords are hidden. SOCKS5 can also use IP allowlisting. If required, allowlist the VPS public IP with the proxy provider.
2. Optionally enter a full Control D DoH URL for this exit. Enter keeps the default Cloudflare DoH resolver. This is the exit's DNS setting, not a per-device Control D profile.
3. Open the **Tailscale authentication link** printed in the terminal and sign in to the same tailnet used by your Apple TV/iPhone. Every country has its own identity and first-time authentication link. Reboots reuse the saved identity.
4. **Exit advertising is enabled automatically. Tailscale approval is separate.** If your tailnet does not auto-approve exits, open [Machines](https://login.tailscale.com/admin/machines), select the new `COUNTRY` node, then **Edit route settings > Use as exit node**. Device approval may also be required if enabled in your tailnet.
5. On Apple TV/iPhone open **Tailscale > Exit Node** and select `COUNTRY`. Each device chooses independently.

You can approve the exit routes from the VPS instead of the website:

```bash
sudo tailscale-proxy approve usa
```

This optional helper asks for a **Tailscale API access token**, not a device auth key. It does not save the token. It verifies a unique hostname, checks the advertised default routes, preserves other enabled routes and confirms both exit routes were approved. Your token needs permission to read devices and read/write device routes. The installer does not change your tailnet policy. Existing `autoApprovers.exitNode` policy can also approve exits automatically.

## Routing

**The destination `45.88.89.23/32` ALWAYS bypasses the upstream proxy and uses the VPS's normal internet connection.** It is the first route rule, applies to every country, and remains in place after edits/restarts. This matches the destination IP, not a proxy host or client address.

All other captured client internet traffic goes through that country's assigned upstream. No direct app-traffic fallback is configured. A failed proxy must fail requests rather than reveal the VPS public IP. Connections to private destinations through the exit are rejected to avoid exposing VPS services. No host SSH, Tailscale SSH, dashboard or public config-download service is enabled by this project.

HTTP proxies support TCP only. UDP is rejected unless you explicitly enable a UDP-capable SOCKS5 or Shadowsocks provider. Some applications fall back from QUIC to TCP; others require working UDP. ICMP is rejected outside the direct exception. This does not turn a TCP-only provider into a full IP VPN. The proxy provider must support any IPv6 destinations you use; failures do not fall back to the VPS.

Tailscale coordination/relay connections and the upstream proxy connection use the VPS network normally. They are infrastructure traffic, not client app-traffic fallback.

## DNS

Tailscale normally uses the selected exit node's DNS. This project handles Tailscale peer DNS using the configured exit DoH resolver **through that exit's upstream proxy**. Only infrastructure lookups for Tailscale and proxy hostnames use the VPS resolver.

For device-specific Control D profiles, use the supported [Tailscale Control D integration](https://tailscale.com/docs/integrations/control-d):

1. Add the Control D Tailscale endpoint's Resolver ID as the global Control D nameserver in Tailscale DNS.
2. Enable **Override DNS servers** and **Use with exit node** on that nameserver. Keep Control D configured globally for overrides to work.
3. Create separate Control D endpoints linked to the profiles you want each device to use.
4. In the Tailscale policy JSON, append `nodeAttrs` entries targeting each client device's Tailscale IP and specifying `controld:RESOLVER_ID?priority=1`. The [Tailscale target reference](https://tailscale.com/docs/reference/targets-and-selectors) allows IP targets for node attributes. Use actual device IPs; the example addresses and resolver IDs below are placeholders.

```json
"nodeAttrs": [
  {
    "target": ["100.64.0.10"],
    "attr": ["controld:APPLE_TV_RESOLVER_ID?priority=1"]
  },
  {
    "target": ["100.64.0.11"],
    "attr": ["controld:IPHONE_RESOLVER_ID?priority=1"]
  }
]
```

Merge these entries with any existing `nodeAttrs`; do not replace the whole policy. A higher priority wins when multiple Control D attributes match a device. Target the **client device**, not the country exit node. A user-email target applies to that user's devices, so it is unsuitable for separating devices owned by one login.

With this integration enabled, each supported Tailscale client selects its own Control D resolver rather than the exit service's fallback resolver. The selected country proxy remains independent. Validate the applied endpoint/profile in Control D Analytics while each real client has an exit selected. This is managed DNS through Tailscale, not a promise to retain the OS device's existing DNS profile. Tailnet policy and Control D endpoints are managed in their respective consoles; this installer does not edit them.

## Commands

| Command | Action |
| --- | --- |
| `sudo add` | Add proxy and create/advertise its Tailscale exit node |
| `sudo manage` | List, edit proxy/DNS, retrieve sign-in link, restart, remove, approve |
| `sudo bench` | Check each proxy's public IP, location, provider and HTTPS request time |
| `sudo check` | Show Tailscale authentication/runtime state and advertised settings |
| `sudo tailscale-proxy login usa` | Show the USA node's current sign-in link |
| `sudo tailscale-proxy approve usa` | Optionally approve exit routes using a token |

Use the full `tailscale-proxy COMMAND` form if a short command is already used by another installation. Exit selectors are the saved slug (for example `usa`) or the printed hostname. Run a command without its optional selector to choose interactively where supported. `bench` without a selector checks all exits.

`check` reports the local backend state. `Running` does not prove tailnet route approval, proxy availability, client exit IP or DNS correctness. `bench` checks the real sing-box upstream proxy path from the VPS using an authenticated loopback probe. It does not test an authenticated remote Tailscale device. Its HTTPS request time includes the request and is not an ICMP ping or throughput result.

Edits retain the node identity and apply only to that country. Invalid configurations or failed local startup restore the previous config. A reachable but broken upstream can still start successfully; run `bench` after changing credentials.

Removing an exit stops/disables its service and deletes its local credentials/state. Delete the offline node from the Tailscale admin page too. Re-adding a removed country requires a new sign-in.

## Network and storage

Each exit reserves one UDP Tailscale port starting at **41641**. The installer/add helper permits that port if UFW is active. Allow the printed UDP port in any provider firewall for direct connections. Tailscale may relay when direct connectivity is unavailable, with a possible streaming performance cost. Outbound HTTPS and UDP must be permitted. No inbound HTTP or HTTPS config ports are needed.

Probe TCP ports start at 20001 and API TCP ports at 22001. They bind to **127.0.0.1 only**, use random secrets, and must not be exposed in a firewall or reverse proxy.

| Path | Contents |
| --- | --- |
| `/etc/tailscale-proxy/state.json` | Root-only registry, including proxy credentials and DNS URLs |
| `/etc/tailscale-proxy/exits/` | Per-exit generated configs, readable by the service account |
| `/var/lib/tailscale-proxy/nodes/` | Persistent per-country Tailscale identities |
| `/opt/tailscale-proxy/` | Installed engine and management source |

Back up both `/etc/tailscale-proxy` and `/var/lib/tailscale-proxy` privately. Keep secrets and state out of the public repository. Consider disabling node key expiry for these persistent exits in Tailscale if that suits your account policy.

```bash
sudo journalctl -u tailscale-proxy@usa -n 50 --no-pager
sudo tailscale-proxy bench usa
```

## Verification

```bash
bash -n install.sh
python3 -m unittest discover -s tests -v
SING_BOX_BIN=/path/to/sing-box python3 -m unittest discover -s tests -v
```

The real-engine tests validate all supported proxy configurations and exercise HTTP proxy routing, the exact direct-bypass predicate and proxy failure isolation. The direct test destination is redirected to a loopback fixture; it does not contact the real `45.88.89.23` service. Test fixtures replace the Tailscale transport with the same runtime's authenticated probe inbound. Full Apple TV/iPhone Tailscale connectivity, exit approval, streaming performance and Control D behaviour still require a real tailnet/device test.
