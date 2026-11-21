# Changelog

## Unreleased

### Changed baseline rules (apply once after upgrading)

These change what DRFW generates for every profile. Your rules and settings stay as they
are; the generated ruleset around them is different.

- **ICMP redirects are really blocked now.** A redirect that refers to one of your
  connections used to be let through as "related" traffic, so "Block ICMP redirects"
  did not stop the redirects that matter. The redirect drops now come first.
- **Multicast group membership (IGMP) is allowed.** IGMP was dropped, so switches with
  multicast snooping stopped sending multicast (UPnP/SSDP, IPTV) to this computer after a
  few minutes. Server Mode now also lets IGMP membership reports and IPv6 "listener done"
  messages out.
- **DHCP replies from a DHCP server (UDP port 67 to 68) are allowed explicitly.** Most
  DHCP clients did not need this, but clients that receive on an ordinary UDP socket do.
- **Anti-spoofing (RPF) only checks new connections and honours the packet mark.** It
  now runs after the accept of established connections and takes the firewall mark into
  account, so full-tunnel VPNs (wg-quick, Tailscale exit nodes) keep working with it on.
  It still drops spoofed source addresses. A VPN peer that contacts this computer first
  over the tunnel's underlay can still be blocked.
- **The ICMP rate limit now limits pings.** It used to limit only the start of new pings,
  so a ping flood was answered in full. Echo requests over the limit are now dropped;
  neighbor discovery and other ICMP are never limited.
- **Strict ICMP accepts all ICMPv6 messages IPv6 needs** (RFC 4890), including router
  solicitations and multicast listener reports, so virtual machines and hotspot clients
  of this computer keep working.
- **Packets with loopback addresses (127.0.0.0/8) arriving from the network are dropped**
  (they only ever arrive when `route_localnet` is enabled, e.g. by kube-proxy).
- **Logging of dropped packets ignores broadcast and multicast**, so LAN noise no longer
  uses up the log rate.

Save to System will report your applied rules as untested until you apply once: the
rules DRFW generates changed, so the record of what you last applied no longer matches.
Apply (and keep) once after upgrading.

### New

- **Local network discovery** (Settings, Desktop mode): find and be found by printers,
  TVs, speakers and other computers on your network (mDNS, UPnP/SSDP, WS-Discovery), and
  receive the answers to this computer's own discovery queries. On for profiles the GUI
  creates from now on (the first profile, "New empty profile", "Start fresh"); off for
  existing profiles, where the GUI asks once whether to turn it on. Turn it off on
  networks you don't trust. The Exposure view shows the discovery sockets as "local
  network (discovery)", not as open.
- **Server Mode offers the essentials.** Switching Server Mode on now offers, pre-ticked,
  ordinary Output rules for DNS, DNS over TLS, time sync (NTP), web and updates (HTTP and
  HTTPS) and ping, so a server can still look up names, set its clock and update. The
  ticked ones are added in one step that Ctrl+Z undoes; rules you already have are not
  offered twice.
- **Rule templates:** "Add from template" (next to Add Access Rule) offers ready-made,
  ordinary rules for the interfaces this computer has: DHCP and DNS for virtual machines
  on libvirt bridges (`virbr*`), and for Tailscale "Tailscale: direct connections" (UDP
  41641) and "Trust tailscale0".
- **Forwarded rules:** with "Block forwarded traffic" on, rules can allow routed traffic
  (for example to containers or virtual machines), matching both the incoming and the
  outgoing interface. They are marked FWD in the rule list, and shown as inactive while
  forwarded traffic is not blocked (like Output rules in Desktop mode).
- **Forwarding warning:** when IP forwarding is on and DRFW does not block forwarded
  traffic, `drfw status`, the Exposure view and the "Commit Changes?" dialog say so:
  containers, VMs or other networks may be reachable through this computer.
- **Docker warning:** ports Docker publishes bypass every input rule (they go through
  the forward chain). The Exposure view and `drfw exposure` now mark them "published by
  Docker: not filtered by DRFW's rules" instead of "nobody", and say so in general when
  Docker or Podman networks exist without a `docker-proxy` to show their ports.
  `drfw exposure --json` has the new fields `published_by_docker` and `local_discovery`.

### Corrected descriptions

- **Anti-spoofing (RPF)** now reads "Drop new connections whose source address could not
  have arrived on that interface. Useful with rules that trust a source address. May
  block peers that contact a full-tunnel VPN first." Docker and libvirt bridges and VPNs
  are no longer said to break.
- **Strict ICMP** no longer claims to break network diagnostics: ping, traceroute and MTU
  discovery keep working; only rarely used types such as timestamp and address-mask
  requests are blocked.
- **ICMP rate limiting** says what it does: "Limit incoming ping requests to N per
  second".
- **Server Mode** is no longer "recommended for servers"; it says that outgoing
  connections need rules, and offers the essential ones.
- **Block forwarded traffic** says that Docker, VMs and VPN routing need Forwarded rules
  with it on (they can now be written).
