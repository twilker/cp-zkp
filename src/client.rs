use auth_lib::bootstrap_client;
use uuid::Uuid;
use std::time::{Instant};
use auth_lib::grpc::chaum_pederson_client::AuthClient;

pub mod auth_client {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connect to server");
    let client = bootstrap_client::<Box<dyn AuthClient>, &str>("http://[::1]:50051").await?;

    println!("Register user");

    let user = Uuid::new_v4().to_string();
    let mut x = auth_lib::calculate_hash(&"My Super Secret Password".to_string());
    client.register_user(&user, &x).await?;

    let now = Instant::now();

    println!("Authenticate user");

    x = auth_lib::calculate_hash(&"My Super Secret Password".to_string());
    let session_token = client.authenticate_user(&user, &x).await?;

    println!("Received session {:?}", session_token);
    println!("Time to authenticate: {}ms", now.elapsed().as_millis());

    Ok(())
}