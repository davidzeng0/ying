# ying
This is currently a WIP. ETA: End of July 2024.

The fastest and highest quality audio player for Discord.

Driven by a custom I/O engine and executed via ultra low overhead light threads,<br>
this library performs up to 1,400% faster than sange, and uses 1/3rds the memory.

(also see previous projects: [xxlink](https://github.com/davidzeng0/xxlink) and [sange](https://github.com/davidzeng0/sange))

This is only the server, similar to lavalink.<br>
The server needs to be running in the background.

To use this with your bot, use the [client](https://github.com/davidzeng0/ying-client) library

#### Requirements
- Linux x86_64
- Linux kernel >= 6.1 (check with `uname -a`)

#### Dependencies (Debian, Ubuntu, Pop_Os!) (other distros figure out yourself)
```bash
sudo apt install -y libopus-dev protobuf-compiler

# Compile FFmpeg latest (make sure all other versions are uninstalled, including the ones from apt)
sudo apt install -y nasm
git clone https://github.com/FFmpeg/FFmpeg
cd FFmpeg
./configure --arch=amd64 --enable-libopus --enable-shared
make -j $(nproc)
sudo make install
cd ..
```

#### Installation
Make sure you have [cargo](https://rustup.rs) installed

```bash
cargo install --git https://github.com/davidzeng0/ying.git
```

#### Run
```bash
# Run ying
ying

# Show help
ying --help

# Bind custom ip (default 127.0.0.1)
ying -i 0.0.0.0

# Bind custom port (default 5360)
ying -p 1337
```
