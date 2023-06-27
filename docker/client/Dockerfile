FROM rust:bookworm as builder

RUN apt-get update \
    && apt-get install -y protobuf-compiler libprotobuf-dev

WORKDIR /usr/src/app
RUN USER=root cargo new --bin auth-client
WORKDIR /usr/src/app/auth-client
COPY ./Cargo.toml ./Cargo.toml
RUN mkdir ./src/lib; mv ./src/main.rs ./src/lib/lib.rs; cargo build --lib --release
RUN rm -rf ./src/lib

ADD . ./

RUN rm ./target/release/deps/auth_*
RUN cargo build --release

FROM debian:bookworm-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=appuser \
    PORT=8000 \
    HOST=server

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /usr/src/app/auth-client/target/release/auth-client ${APP}/auth-client

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["tail", "-f", "/dev/null"]