---
name: "ipc-auth-audit"
description: "Audits local IPC channels (pipes, sockets, MCP, RPC, shared memory) for missing authentication/authorization. Invoke for local attack-surface security review, bug bounty, or red-team assessment."
---

# Local IPC Authentication & Authorization Audit

Systematically assess a product's local inter-process communication (IPC) channels
(named pipes, Unix sockets, MCP transports, RPC endpoints, shared memory) for
missing authentication or authorization. The goal is to determine whether an
unprivileged or unrelated local process can reach a privileged/trusted process's
capabilities directly, without a valid handshake or identity check.

## When to use

Invoke this skill when the user asks to:

- Audit the local attack surface of an application, agent tool-host, IDE plugin, or MCP server.
- Find local privilege-escalation or auth-bypass vulnerabilities.
- Review whether a product's local channels are properly isolated.
- Reproduce or generalize a "no-auth local IPC" finding into a reusable methodology.

Do NOT use this skill for remote/web vulnerabilities, memory corruption analysis, or
network protocol fuzzing beyond the loopback/local boundary.

## Phase 0 - Authorization gate (non-negotiable)

Before any enumeration, record and confirm scope:

- Only audit products you own, or for which you have explicit written permission
  (security research agreement, bug bounty program, client authorization).
- Confirm the exact product, component, and version in scope.
- Agree on limits: PoC must be minimal, reversible, non-persistent, and must not
  read, modify, or exfiltrate real user data or credentials.
- Record the authorization source (agreement / program ID) in the report.

Stop and ask the user to confirm authorization if any target is not clearly in scope.

## Phase 1 - Enumerate the attack surface

Inventory every local IPC channel the target process exposes. A channel is anything
another local process can connect to or write into.

Windows:
- Named pipes: `Get-ChildItem '\\.\pipe\'` and `pipelist.exe`
- ALPC/LPC ports: `\RPC Control\*` (not visible via `Get-ChildItem`; use `handle.exe` or Process Explorer)
- DCE/RPC over `ncalrpc` endpoints (use RpcView; `netstat` does not show these)
- Loopback TCP/UDP: `netstat -ano` filtered to `127.0.0.1`
- COM objects registered in the current user session
- Shared memory / memory-mapped files, named events, semaphores, mutexes (via `handle.exe`)

Unix-like:
- Unix domain sockets including abstract `@name` sockets (`ss -xlp`, `lsof -U`)
- Loopback TCP (`ss -tlnp`)
- D-Bus system and session buses
- Shared memory segments (`ipcs -m`)

MCP (Model Context Protocol) transports:
- stdio, HTTP (SSE), and streamable HTTP — test each transport separately.

Handle-level view (critical):
- Determine WHO holds handles to WHAT, not just what exists. Use Sysinternals
  `handle.exe` / `accesschk.exe`, `lsof`, or `/proc/<pid>/fd`.

Module scan (feeds Phase 2):
- Identify linked libraries in the target process (`dumpbin`, `ldd`, or process
  module list). Look for thrift, gRPC, protobuf, or RPC libraries.

Output: a channel inventory table: `channel type | path/id | owner process | PID | notes`.

## Phase 2 - Identify the protocol

Separate transport from protocol. Do not assume a protocol just from the channel type:

- gRPC is HTTP/2 over TCP and rarely runs over named pipes.
- Named pipes more commonly carry Thrift or a custom TLV/binary protocol.
- Unix sockets may carry JSON-RPC, protobuf, or a custom line protocol.

Fastest protocol fingerprint:
- Open the channel and send an empty or malformed frame. Read the error echo —
  it frequently leaks the library name, version, and protocol type.

Magic bytes / preambles:
- gRPC client preface: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
- Thrift binary protocol: leading version byte / message name
- protobuf: field-tag structure (wire type + field number)

Static analysis:
- Strings in the binary, imported libraries, PDB/symbols, embedded protobuf
  descriptors. If gRPC reflection is enabled, `grpcurl ls` or `grpc_cli ls`
  enumerates methods directly.

Dynamic analysis:
- Pipe I/O capture (Process Monitor), API hooking (Frida), loopback capture
  (npcap + Wireshark). Note: some products are anti-debug; when dynamic capture
  fails, close the loop with static analysis + protocol guessing.

Output: protocol + version, and the method list if reflection/discovery is available.

## Phase 3 - Probe authentication and authorization (the crux)

Treat these as three independent axes; test each separately:

1. Encryption — is the channel plaintext or encrypted? Plaintext enables passive
   capture and replay.
2. Authentication — does connect/handshake require an auth frame, session
   negotiation, or version exchange? What error appears when it is skipped?
3. Authorization — even if a connection succeeds, does the server validate the
   caller? Connection success does NOT imply the ability to invoke anything.

First action — read the channel's DACL (do this before sending any frame):
- Windows: `accesschk.exe \\.\pipe\<name>` or `GetSecurityInfo` on the pipe;
  `accesschk` on the file/COM/RPC object.
- Unix: `ls -l` on the socket file; check D-Bus policy XML.
- This directly answers "who is allowed to connect" earlier and more reliably
  than any probe frame.

Authorization checks to look for on the server:
- `GetNamedPipeClientProcessId` / client PID validation
- Caller image path, signature, integrity level, or Session check (incl. Session 0 isolation)
- Per-command authorization vs. per-connection only

Distinguish and record separately:
- Spoofing (forge a session_id / token / PID) vs. replaying (reuse a captured
  valid frame). These differ by an order of magnitude in difficulty.

Stateful vs. stateless:
- Determine whether the server re-validates on every connection. A stateless
  channel makes replay feasible; a stateful channel may not.

Impersonation (privilege escalation signal):
- If the server calls `ImpersonateNamedPipeClient`, a successful connection may
  let you execute in the victim process's context — this is privilege escalation,
  not merely invocation. Note it explicitly.

Output: a per-channel matrix: `channel | encryption | authN | authZ | stateful? | impersonation? | can-connect | can-invoke`.

## Phase 4 - Verify capability (minimal, non-destructive)

- Enumerate the RPC contract / command set first (list methods). Then pick the
  single highest-impact, least-destructive capability to verify.
- Verify with a marker-file write or a harmless sentinel read ONLY:
  - No real credential reads, no data exfiltration, no payload drop, no persistence.
- Record the execution context precisely: does the verified action run in YOUR
  process context, or in the victim/impersonated context?
- Keep a full evidence chain: exact commands, inputs, outputs, timestamps.

## Phase 5 - Report

Use this template for every finding:

1. Product / component / version
2. Channel and protocol (from Phases 1-2)
3. Root cause (which auth/authz check is missing or bypassable)
4. PoC (minimal, sanitized; no real secrets)
5. Impact + CVSS + severity; note victim-context if impersonation applies
6. CWE mapping: CWE-306 (missing authentication for critical function),
   CWE-862 (missing authorization), CWE-290 (auth bypass via identity spoofing)
7. Confidence: end-to-end tested vs. static inference — mark explicitly
8. Remediation: add ACL on the channel, bind to owning process token / session
   handshake, enforce per-command authorization, restrict terminal/file-read surfaces

## Safety rules (hard constraints)

- Authorized scope only; document the authorization source in every report.
- Minimal, reversible, non-persistent verification only.
- Never exfiltrate data, harvest credentials, or access targets outside scope.
- Report findings to the owner/vendor through the agreed channel; do not weaponize
  for unauthorized targets.

## Command/tool cheat sheet

| Purpose | Windows | Unix-like |
|---|---|---|
| List named pipes | `pipelist.exe`, `Get-ChildItem '\\.\pipe\'` | — |
| List sockets | `netstat -ano` (loopback) | `ss -xlp`, `lsof -U` |
| Handle/owner view | `handle.exe`, `accesschk.exe` | `lsof`, `/proc/<pid>/fd` |
| Read channel DACL | `accesschk.exe \\.\pipe\<name>` | `ls -l <socket>` |
| RPC endpoint discovery | RpcView | `busctl`, `gdbus introspect` |
| Protocol reflection | `grpcurl ls`, `grpc_cli ls` | same |
| Dynamic capture | Process Monitor, Frida | `strace`, Frida, `tcpdump -i lo` |
| Loopback capture | npcap + Wireshark | `tcpdump -i lo -w` |

## Methodology summary (one screen)

```
Phase 0  Threat model + authorization gate
Phase 1  Enumerate local IPC channels (pipes / sockets / ALPC / RPC / MCP / shm)
Phase 2  Identify protocol (transport != protocol; empty-frame fingerprint first)
Phase 3  Probe auth/authz/encryption (read DACL first; the crux)
Phase 4  Verify capability (enumerate contract, then minimal marker test)
Phase 5  Report (root cause -> PoC -> impact -> CWE/CVSS -> remediation)
```