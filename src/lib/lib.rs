pub mod chaum_pedersen;
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

pub mod cp_grpc {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

pub struct Config {
    pub bit_size: u16,
    pub fixed_parameters: bool
}

impl Config {
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
        }
    }
}

pub fn bootstrap_server(config: Option<Config>) -> impl Auth {
    let config = config.unwrap_or(Config::build());
    let parameters = ChaumPedersenAlgorthim::find_parameters(config.bit_size, config.fixed_parameters);
    let algorithm = Arc::new(RwLock::new(ChaumPedersenAlgorthim::new(&parameters)));
    let data_access = Arc::new(RwLock::new(MapDataAccess::new()));
    let validation = Arc::new(RwLock::new(ChaumPedersenValidationImpl::new(data_access.clone())));
    let logic = Arc::new(RwLock::new(ChaumPedersenLogicImpl::new(algorithm.clone(), data_access.clone(), validation.clone())));
    CPAuthServer::new(logic)
}

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

pub fn calculate_hash<T: Hash>(t: &T) -> BigInt {
    let mut s = FxHasher::default();
    t.hash(&mut s);
    s.finish().to_bigint().unwrap()
}