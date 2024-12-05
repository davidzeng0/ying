# ying
This is currently a WIP. ETA: A long time.

The fastest and highest quality audio player for Discord.

Driven by a custom I/O engine and executed via ultra low overhead light threads,<br>
this library performs up to 1,400% faster than sange, and uses 1/3rds the memory, or ~2,500% faster than lavaplayer.

(also see previous projects: [xxlink](https://github.com/davidzeng0/xxlink) and [sange](https://github.com/davidzeng0/sange))

This is only the server, similar to lavalink.<br>
The server needs to be running in the background.

To use this with your bot, use the [client](https://github.com/davidzeng0/ying-client) library

## Running

### Requirements

#### Linux users
- Docker
- Kernel >= 5.6 (check with `uname -a`, version 6.1 or later recommended for best performance)

#### Windows & Mac users
- Docker (use linux for best performance)

```sh
# Build docker image
curl "https://raw.githubusercontent.com/davidzeng0/ying/main/Dockerfile" | docker build -t ying -f - .

# Start ying
docker run -d --restart always -p 5360:5360 ying [OPTIONS]

# Options
# Show help
ying --help

# Bind custom ip (default 127.0.0.1)
ying -i 0.0.0.0

# Bind custom port (default 5360)
ying -p 1337
```
