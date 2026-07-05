# idiod - Block abusive source IP addresses

idiod is a Linux daemon that watches request activity and uses nftables to temporarily block source addresses that appear abusive.

## What it does

- Receives request events (e.g. from the provided Apache log filter) over a Unix domain socket.
- Tracks repeated activity from individual IP addresses.
- Applies temporary nftables rules to block offending addresses.
- Can also install a temporary global rate limit when new-peer activity becomes very high.
- Removes those rules automatically after their timeout expires.

## Requirements

- Linux with nftables support and the `nft` command available.
- systemd.
- A Rust toolchain with `cargo`.

## Build

Run:

```sh
./build.sh
```

This builds the workspace, runs the test suite, and produces executable binaries.

## Install

Run as root:

```sh
./install.sh
```

The install script places the binaries under `/opt/idiod/bin`, installs a sample configuration at `/opt/idiod/etc/idiod.toml`, and installs the systemd units `idiod.service` and `idiod.socket`.

## Configuration

After installation, edit `/opt/idiod/etc/idiod.toml`.

The configuration file controls:

- peer and timeout settings
- global rate-limit thresholds
- per-peer rate thresholds
- path allowlisting
- block timeout settings
- scoring thresholds and decay behavior

## Running with Apache

The included `idiod-apache-logfilter` binary reads Apache access log lines from standard input, writes a sanitized copy to an output file, and forwards relevant request information to the idiod daemon.

It must be configured in Apache's configuration to filter access logs through it.
For example:

```
CustomLog "|/opt/idiod/bin/idiod-apache-logfilter /var/log/apache2/ssl_access.log" combined
```

## Service management

The installed systemd units are:

- `idiod.socket`
- `idiod.service`

The daemon listens on the Unix socket at `/run/idiod/idiod.sock`.

## License

Spdx-License-Identifier: MIT OR Apache-2.0
