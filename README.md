# matscan

silly minecraft server scanner

matscan is heavily inspired by [masscan](https://github.com/robertdavidgraham/masscan), and like masscan contains its own tcp stack for maximum speed.

## Features

- Adaptive scanning (scans more than just the default port)
- Works well even on relatively low scan rates and with lots of packet drops (running in production at ~50kpps)
- Can be run in a distributed fashion
- Customizable rescanning (rescan servers with players online more often, etc)
- Customizable target host, target port, protocol version
- Send to a Discord webhook when a player joins/leaves a server
- Detection of duplicate servers that have the same server on every port
- Protocol implementation fingerprinting (can identify vanilla, paper, fabric, forge, bungeecord, velocity, node-minecraft-protocol)
- Historical player tracking
- Offline-mode detection
- Written in Rust 🚀🚀🚀

## Note

I highly encourage you to make your own server scanner instead of relying on someone else's code, I promise you'll have a lot more fun that way.
The code for matscan is provided as-is; I do not provide support for running matscan and breaking changes may be pushed to this repo without warning.

## Usage

It is assumed that you know the basics of server scanning. Otherwise, I recommend reading the [masscan readme](https://github.com/robertdavidgraham/masscan/blob/master/README.md) and [documentation](https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown). Also be aware that matscan only supports Linux, but you probably shouldn't be running it at home anyways.

Rename `example-config.toml` to `config.toml` and fill in the fields.

Installing Postgres with the [pg-uint128](https://github.com/pg-uint/pg-uint128) extension is required.

Then, can make the database with the following queries:
```sql
CREATE DATABASE matscan;
CREATE USER matscan WITH PASSWORD 'replace me!!!';
GRANT ALL PRIVILEGES ON DATABASE matscan TO matscan;
GRANT CREATE ON SCHEMA public TO matscan;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO matscan;

-- the user will need superuser permissions on the first run to enable postgres extensions
ALTER ROLE matscan superuser;
-- after the first run, you should do ALTER ROLE matscan nosuperuser;

-- PostgreSQL URI is postgres://matscan:replace-me@localhost/matscan
```

To run matscan, use the following:
```sh
# Firewall port 61000 so your OS doesn't close the connections
# Note: You probably want to use something like iptables-persistent to save this across reboots
iptables -A INPUT -p tcp --dport 61000 -j DROP

# Run in release mode
cargo b -r && sudo target/release/matscan
```

You can also use the binary without the rest of the code as long as you put the `config.toml` and `exclude.conf` in the same directory as it.
