use auth_lib::cp_grpc::auth_server::AuthServer;
use auth_lib::bootstrap_server;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let auth_server = bootstrap_server(None);

    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(addr)
        .await?;

    Ok(())
}