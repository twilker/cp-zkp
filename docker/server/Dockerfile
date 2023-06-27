FROM rust:bookworm as builder

RUN apt-get update \
    && apt-get install -y protobuf-compiler libprotobuf-dev

WORKDIR /usr/src/app
RUN USER=root cargo new --bin auth-server
WORKDIR /usr/src/app/auth-server
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
    BIT_SIZE=256 \
    FIXED_PARAMETERS=true \
    PORT=8000 \
    HOST=127.0.0.1

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /usr/src/app/auth-server/target/release/auth-server ${APP}/auth-server

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./auth-server"]