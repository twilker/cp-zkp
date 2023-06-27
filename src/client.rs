use auth_lib::bootstrap_client;
use auth_lib::grpc::chaum_pedersen_client::AuthClient;
use clap::{Parser, Subcommand};

pub mod auth_client {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// only registers the user
    Register {  
        /// Sets the user name
        #[arg(short, long)]
        name: String,

        /// Turn debugging information on
        #[arg(short, long)]
        password: String,
    },

    /// authenticates the user and returns the session token
    Login {   
        /// Sets the user name
        #[arg(short, long)]
        name: String,

        /// Turn debugging information on
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
 
    println!("Connect to server");
    let config = auth_lib::Config::build();
    let client = bootstrap_client::<Box<dyn AuthClient>, String>(format!("http://{}:{}", config.host, config.port)).await?;
    
    match cli.command {
        Commands::Register { name, password } => {
            println!("Register user");

            let x = auth_lib::calculate_hash(&password);
            client.register_user(&name, &x).await?;
            
            println!("User registered");
        },
        Commands::Login { name, password } => {
            println!("Authenticate user");

            let x = auth_lib::calculate_hash(&password);
            let session_token = client.authenticate_user(&name, &x).await?;

            println!("Received session {:?}", session_token);
        },
    }

    Ok(())
}