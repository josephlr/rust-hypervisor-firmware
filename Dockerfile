# Get Nightly Rust matching our version
FROM alpine:3.11 AS nightly

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
COPY ./rust-toolchain .

RUN set -eux; \
    apk add --no-cache ca-certificates gcc musl-dev; \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-musl/rustup-init"; \
    wget -q "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path \
    --default-toolchain $(cat ./rust-toolchain) \
    --profile minimal \
    --component rust-src clippy rustfmt; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME;

FROM nightly AS builder
RUN cargo install cargo-xbuild --vers=0.5.28
COPY make-test-disks.sh .
RUN apk add --no-cache bash mtools file && bash ./make-test-disks.sh

# Stage 3: Copy binaries into reduced image
FROM nightly
COPY --from=builder /usr/local/cargo/bin/cargo-xbuild /bin/
# COPY --from=builder /*.img /
# RUN set -eux; \
#     ver=28660; \
#     file="clear-${ver}-kvm.img.xz"; \
#     url="https://cdn.download.clearlinux.org/releases/${ver}/clear/${file}"; \
#     wget -q "${url}"; \
#     unxz "${file}";
