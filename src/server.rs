use auth_lib::cp_grpc::auth_server::AuthServer;
use auth_lib::{bootstrap_server, Config};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::build();
    let addr = format!("{}:{}", config.host, config.port).parse()?;
    let auth_server = bootstrap_server(Some(config));

    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(addr)
        .await?;

    Ok(())
}