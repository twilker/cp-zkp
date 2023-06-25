mod chaum_pedersen;
mod data_access;
mod grpc;

use std::sync::Arc;
use std::env;
use auth_server::auth_server::{Auth, AuthServer};
use tokio::sync::RwLock;
use tonic::{transport::Server};
use chaum_pedersen::algorithm::{ChaumPedersen, ChaumPedersenAlgorthim};
use data_access::map_access::MapDataAccess;
use grpc::chaum_pederson_server::CPAuthServer;

const DEFAULT_BIT_SIZE: &str = "256";

pub mod auth_server {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

pub struct Config {
    pub bit_size: u16
}

impl Config {
    pub fn build() -> Config {
        Config {
            bit_size: env::var("BIT_SIZE")
                .unwrap_or(String::from(DEFAULT_BIT_SIZE))
                .parse::<u16>()
                .expect("BIT_SIZE must be a number"),
        }
    }
}

fn bootstrap() -> impl Auth {
    let config = Config::build();
    let parameters = ChaumPedersenAlgorthim::find_parameters(config.bit_size);
    let algorithm = Arc::new(RwLock::new(ChaumPedersenAlgorthim::new(&parameters)));
    let data_access = Arc::new(RwLock::new(MapDataAccess::new()));
    CPAuthServer::new(algorithm, data_access)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let auth_server = bootstrap();

    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(addr)
        .await?;

    Ok(())
}