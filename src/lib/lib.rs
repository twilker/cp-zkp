#![warn(missing_docs)]
//! # Chaum-Pedersen Zero-Knowledge Proof Authentication
//! This crate provides a Chaum-Pedersen zero-knowledge proof authentication scheme.
//! It provides functionality for both a server and a client using gRPC.

#[doc(hidden)]
pub mod chaum_pedersen;
#[doc(hidden)]
pub mod grpc;
mod data_access;
mod logic;

use std::{sync::Arc, sync::RwLock, error::Error};
use std::env;
use cp_grpc::auth_server::Auth;
use grpc::chaum_pedersen_client::AuthClient;
use logic::chaum_pedersen_logic::ChaumPedersenLogicImpl;
use logic::chaum_pedesen_validation::ChaumPedersenValidationImpl;
use chaum_pedersen::algorithm::{ChaumPedersenAlgorthim, ChaumPedersenParameters};
use data_access::map_access::MapDataAccess;
use grpc::{chaum_pedersen_server::CPAuthServer, chaum_pedersen_client::CPAuthClient};
use std::{hash::{Hash, Hasher}};
use num_bigint::{BigInt, ToBigInt, Sign};
use rustc_hash::FxHasher;
use tonic::codegen::StdError;

const DEFAULT_BIT_SIZE: &str = "256";
const DEFAULT_FIXED_PARAMETERS: &str = "false";
const DEFAULT_PORT: &str = "50051";
const DEFAULT_HOST: &str = "[::1]";

#[doc(hidden)]
pub mod cp_grpc {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// The configuration for the Chaum-Pedersen authentication scheme
/// It reads arguments from the environment variables and provides default values for missing environment variables.
/// # Example
/// This is how the configuration can be modified inside the code:
/// ```
/// # use auth_lib::Config;
/// let mut config = Config::build();
/// config.bit_size = 128;
/// ```
pub struct Config {
    /// The bit size of the prime number used in the algorithm
    /// 
    /// Default: 256
    pub bit_size: u16,
    /// Whether to use fixed parameters or generate new ones
    /// Caution! If this is set to true and the bit size is bigger than 256,
    /// it will take a long time for the server to start.
    /// 
    /// Default: false
    pub fixed_parameters: bool,
    /// The port on which the server will listen
    /// 
    /// Default: 50051
    pub port: u16,
    /// The host on which the server will listen
    /// 
    /// Default: [::1]
    pub host: String
}

impl Config {
    /// Builds the configuration from the environment variables
    pub fn build() -> Config {
        Config {
            bit_size: env::var("BIT_SIZE")
                .unwrap_or(String::from(DEFAULT_BIT_SIZE))
                .parse::<u16>()
                .expect("BIT_SIZE must be a number"),
            fixed_parameters: env::var("FIXED_PARAMETERS")
                .unwrap_or(String::from(DEFAULT_FIXED_PARAMETERS))
                .parse::<bool>()
                .expect("FIXED_PARAMETERS must be a boolean"),
            port: env::var("PORT")
                .unwrap_or(String::from(DEFAULT_PORT))
                .parse::<u16>()
                .expect("PORT must be a number"),
            host: env::var("HOST")
                .unwrap_or(String::from(DEFAULT_HOST)),
        }
    }
}

/// Builds the server with the given configuration.
/// If no configuration is given, it will use the default configuration.
/// 
/// # Example
/// This is how the server can be started:
/// ```
/// # use auth_lib::Config;
/// # use auth_lib::bootstrap_server;
/// use auth_lib::cp_grpc::auth_server::AuthServer;
/// 
/// # let mut config = Config::build();
/// # config.fixed_parameters = true;
/// let server = bootstrap_server(Some(config));
/// let addr: std::net::SocketAddr = "[::1]:50051".parse()?;
/// 
/// // This is the ready-to-use grpc server
/// let grpc_server = AuthServer::new(server);
///
/// // Usable in a tonic server like this:
/// /*tonic::transport::Server::builder()
///    .add_service(AuthServer::new(server))
///    .serve(addr)
///    .await?;
/// */
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn bootstrap_server(config: Option<Config>) -> impl Auth {
    let config = config.unwrap_or(Config::build());
    let parameters = ChaumPedersenAlgorthim::find_parameters(config.bit_size, config.fixed_parameters);
    let algorithm = Arc::new(RwLock::new(ChaumPedersenAlgorthim::new(&parameters)));
    let data_access = Arc::new(RwLock::new(MapDataAccess::new()));
    let validation = Arc::new(RwLock::new(ChaumPedersenValidationImpl::new(data_access.clone())));
    let logic = Arc::new(RwLock::new(ChaumPedersenLogicImpl::new(algorithm.clone(), data_access.clone(), validation.clone())));
    CPAuthServer::new(logic)
}

/// Builds the client with the given configuration.
/// If no configuration is given, it will use the default configuration.
/// It automatically connects to the given destination and retrieves the parameters from the server.
pub async fn bootstrap_client<T, D>(destination: D) -> Result<Box<dyn AuthClient>, Box<dyn Error>>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<StdError>,
{    
    let mut client = cp_grpc::auth_client::AuthClient::connect(destination).await?;
        
    let parameter_response = client.get_authentication_parameters(tonic::Request::new({})).await?;
    
    let encoded_parameters = parameter_response.into_inner();    
    let parameters = ChaumPedersenParameters {
        p: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.p),
        q: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.q),
        g: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.g),
        h: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.h),
        bit_size: encoded_parameters.bit_size as u16
    };
    let algorithm = ChaumPedersenAlgorthim::new(&parameters);
    let client = CPAuthClient::new(Arc::new(tokio::sync::RwLock::new(client)), Arc::new(tokio::sync::RwLock::new(algorithm)));
    Ok(Box::new(client))
}

#[doc(hidden)]
pub fn calculate_hash<T: Hash>(t: &T) -> BigInt {
    let mut s = FxHasher::default();
    t.hash(&mut s);
    s.finish().to_bigint().unwrap()
}