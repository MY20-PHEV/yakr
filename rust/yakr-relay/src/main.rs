use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use yakr_relay::{create_app, BlobStore};

#[derive(Parser)]
#[command(name = "yakr-relay")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    #[arg(long, default_value = "relay")]
    name: String,
    #[arg(long, default_value = "relay-data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let store = BlobStore::new(args.data_dir, 64 * 1024, 256);
    let app = create_app(store, args.name);
    let addr: SocketAddr = args.listen.parse().expect("valid listen address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("yakr-relay listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}
