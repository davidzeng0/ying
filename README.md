# ying

Audio Player for Discord. (also see [xxlink](https://github.com/davidzeng0/xxlink))

This is only the server, similar to lavalink.<br>
The server needs to be running in the background.

To use this with your bot, see the following list of client libraries
- [Node.js](https://github.com/davidzeng0/ying-client-node) (ying-client-node)

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

```
cargo install --git https://github.com/davidzeng0/ying.git
```

#### Run
```
# Run ying
ying

# Show help
ying --help

# Bind custom ip
ying -i 0.0.0.0
```