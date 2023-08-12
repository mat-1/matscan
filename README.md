# matscan

silly minecraft server scanner

matscan is heavily inspired by [masscan](https://github.com/robertdavidgraham/masscan), and like masscan contains its own tcp stack for maximum speed.

## Features

- Adaptive scanning (scans more than just the default port)
- Works well even on relatively low scan rates and with lots of packet drops (running in production at ~70kpps and ~20% loss)
- Can be run in a distributed fashion
- Customizable rescanning (rescan servers with players online more often, etc)
- Customizable target host, target port, protocol version
- Send to a Discord webhook when a player joins/leaves a server
- Detection of duplicate servers that have the same server on every port
- Protocol implementation fingerprinting (can identify vanilla, paper, fabric, forge, bungeecord, velocity, node-minecraft-protocol)
- Written in Rust 🚀🚀🚀

## Note

I highly encourage you to make your own server scanner instead of relying on someone else's code, I promise you'll have a lot more fun that way.
Also if you do intend on using any of the code here, please read the [license](LICENSE).

## Usage

Rename `config.toml.example` to `config.toml` and fill in the fields.

You'll also have to make a MongoDB database called `mcscanner` with two collections called `servers` and `bad_servers`. You should add indexes for `addr+port` and `timestamp` for the `servers` collection.

```sh
# Firewall port 61000 so your OS doesn't close the connections
iptables -A INPUT -p tcp --dport 61000 -j DROP

# Run in release mode
cargo b -r && sudo ./target/release/matscan
```
