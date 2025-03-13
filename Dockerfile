FROM rust:1.79.0

ARG TARGETARCH
ARG FFMPEG_VERSION="ffmpeg-n7.0-latest-linux%ARCH%-lgpl-shared-7.0"

RUN apt update && \
	apt install -y protobuf-compiler libclang-15-dev pkg-config libopus-dev curl && \
	apt clean

RUN if [ "$TARGETARCH" = "amd64" ]; then \
	export ARCH="64"; \
	elif [ "$TARGETARCH" = "arm64" ]; then \
	export ARCH="arm64"; \
	else \
	echo "Unsupported architecture: $TARGETARCH"; \
	exit 1; \
	fi && \
	export FFMPEG_BUILD=$(echo "$FFMPEG_VERSION" | sed "s/%ARCH%/$ARCH/g") && \
	curl -L -O "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/$FFMPEG_BUILD.tar.xz" && \
	tar -xf $FFMPEG_BUILD.tar.xz && \
	rm $FFMPEG_BUILD.tar.xz && \
	mv $FFMPEG_BUILD ffmpeg && \
	\
	cp -r ffmpeg/bin/* /usr/local/bin && \
	cp -r ffmpeg/include/* /usr/local/include && \
	cp -r ffmpeg/lib/* /usr/local/lib && \
	rm -rf ffmpeg && \
	ffmpeg -version

RUN RUSTFLAGS="-C target-cpu=native" cargo install --git https://github.com/davidzeng0/ying.git
EXPOSE 5360
ENTRYPOINT [ "/bin/bash", "-c", "RUST_BACKTRACE=full", "cargo", "run", "--" ]
