# Wazoo documentation

In this file I will guide you to use wazoo library correctly.

- `blog/`. Original blog post about this project

# Setup

Install with **pip**

```sh
pip install wazoo
```

Install with **uv** (recomended)

```sh
uv add wazoo
```

This installation will give you access to **wazoo** library.

# Classes

In this section I will show you the main classes and what each do.

## Server

- class: `wazoo/server.py`

This class you can make your own wazuh server.

`WazuhServer` opens two TCP servers:

- **Registration server** (default port `1515`, TLS): enrolls new agents. It
  parses the `OSSEC A:'...' V:'...'` message, validates the enrollment password
  (if configured), stores the agent in the database and appends it to
  `client.keys`, then replies with the generated key.
- **Logging server** (default port `1514`): reads length-framed AES/zlib secure
  messages from agents, validates the MD5 checksum, answers control messages
  (startup / keepalive with an `ACK`) and forwards log events to the configured
  `WazooLog` through a `BufferQueue`.

Agents are persisted in a SQLite database (`agents.db` by default) via
`WazuhAgentRepository` and kept in sync with the `client.keys` file. Agent id
`0` is always the manager itself.

```python
import uvloop
from pathlib import Path
from wazoo import WazuhServer, WazooLog

log = WazooLog({"path": "wazoo.log"}, option="file")

server = WazuhServer(
    host="0.0.0.0",
    port_registration=1515,
    port_logging=1514,
    password=None,              # or the enrollment password / authd.pass content
    client_keys="client.keys",
    ssl_path=Path("./ssl"),     # must contain key.pem and cert.pem
    db_path="agents.db",
    log=log,
    max_time_flush=1,           # flush buffered logs every 1s
    max_line_flush=-1,          # no line limit
)

uvloop.run(server.start())
```

Main options:

| Argument | Default | Description |
| --- | --- | --- |
| `host` | `0.0.0.0` | Bind address |
| `port_registration` | `1515` | Enrollment (TLS) port |
| `port_logging` | `1514` | Log ingestion port |
| `password` | `None` | Enrollment password (string). `None` disables it |
| `client_keys` | `client.keys` | Path to the Wazuh client keys file |
| `ssl_path` | `./ssl` | Directory holding `key.pem` and `cert.pem` |
| `db_path` | `agents.db` | SQLite agents database |
| `log` | `None` | A `WazooLog` sink for forwarded events |
| `workers` | `None` | Threads used to offload AES/zlib decoding |
| `max_time_flush` | `1` | Seconds between buffer flushes |
| `max_line_flush` | `-1` | Lines before a forced flush (`-1` = unlimited) |

> A valid TLS `key.pem` / `cert.pem` pair is required in `ssl_path`. You can
> generate a self-signed pair with `scripts/generate_ssl.sh`.

## Wazoo Log

- class: `wazoo/log.py`

This class you can send logs over TCP, UDP, Unix and File log.

`WazooLog` is the output sink where the server forwards decoded agent events.
Pick the transport with `option` and pass its parameters in `data`:

| Option | Required params | Description |
| --- | --- | --- |
| `tcp` | `ip`, `port`, (`ssl`) | Send logs over TCP, optionally with TLS |
| `udp` | `ip`, `port` | Send logs over UDP |
| `unix` | `path` | Write to a Unix domain socket (e.g. `/var/wazoo.sock`) |
| `file` | `path` | Append logs to a file |

```python
from wazoo import WazooLog

# Forward to a SIEM over TCP
log = WazooLog({"ip": "10.0.0.5", "port": 5514, "ssl": False}, option="tcp")

# Or simply append to a file
log = WazooLog({"path": "wazoo.log"}, option="file")

await log.connect()
await log.sendLog(b"hello world")
await log.close()
```

`prefix` prepends a fixed string to every line and `add_new_line` (default
`True`) controls whether each event ends with `\n`.

## Wazoo helper

- class: `wazoo/wazuh/helper.py`

This is the class that you can handle all wazuh agent.

`WazuhHelper` implements the Wazuh secure-message protocol used between the
manager and its agents. It is mostly used internally by the server, but it is
exposed if you need to build tooling around the protocol:

- `parseMessageHeader(msg)` — extract the agent id and AES payload from a raw
  `!<id>!#AES:<data>` frame.
- `decodeSecMessage(agent, aes_data)` — AES-CBC decrypt + zlib decompress into a
  `DecodedMessage`.
- `encodeSecMessage(agent, event, ...)` — build an encrypted, length-framed
  reply for an agent.

`DecodedMessage` exposes the parsed fields (`get_event()`, `is_valid_checksum`,
`is_control_message()`), and encryption keys come from `WazuhAgent.aes_key`
(the MD5 of the agent key).

# Command line

Wazoo also ships as an executable module. Run the manager directly:

```sh
python -m wazoo --host 0.0.0.0 -rp 1515 -lp 1514 --ssl ./ssl -v
```

Useful flags:

| Flag | Default | Description |
| --- | --- | --- |
| `-rp`, `--registration-port` | `1515` | Registration server port |
| `-lp`, `--logging-port` | `1514` | Logging server port |
| `-p`, `--password` | `None` | Enrollment password, or a file such as `authd.pass` |
| `--host` | `0.0.0.0` | Bind address |
| `--ssl` | `./ssl` | SSL directory (`key.pem` + `cert.pem`) |
| `--name` | `manager` | Manager name |
| `--db` | `agents.db` | Agents database path |
| `-w`, `--workers` | `os.cpu_count()` | Decoding worker threads |
| `--processes` | `1` | Worker processes (reuses the port when `> 1`) |
| `-ck`, `--client-keys` | `client.keys` | Client keys file |
| `-b`, `--background` | `False` | Detach and run in the background |
| `--pid-file` | `wazoo.pid` | PID file used with `--background` |
| `-c`, `--config` | `None` | YAML config file (overrides the defaults above) |
| `-v`, `--verbose` | `False` | Verbose logging |

## Config file

Instead of passing everything on the command line, point `--config` at a YAML
file. Values there override the CLI defaults:

```yaml
log:
  option: file
  path: wazoo.log
buffer:
  time_flush: 1   # flush before 1 sec
  line_flush: -1  # does not have a limit
password: authd.pass
processes: 1
workers: -1       # will use os.cpu_count()
```

```sh
python -m wazoo -c config.yml
```
