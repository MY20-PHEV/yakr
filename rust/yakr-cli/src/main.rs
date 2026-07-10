use std::path::PathBuf;
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use yakr_core::{
    invite::create_invite,
    message::{OuterBlob, RelayBlobJson},
    pairing::{build_pairing_request, inviter_complete_pairing, joiner_complete_pairing},
    session::Session,
    store::FileLocalStore,
    Contact, Identity,
};
use yakr_crypto::x25519_generate_keypair;

#[derive(Parser)]
#[command(name = "yakr", about = "Yakr reference client (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    Show {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    ExportPublic {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    Send {
        contact: String,
        message: String,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay: String,
        #[arg(long)]
        home: Option<PathBuf>,
    },
    Fetch {
        contact: String,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay: String,
        #[arg(long)]
        home: Option<PathBuf>,
    },
}

fn home_dir(home: Option<PathBuf>, name: &str) -> PathBuf {
    home.unwrap_or_else(|| {
        std::env::var("YAKR_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs_home().join(".yakr").join(name)
            })
    })
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn store_at(home: Option<PathBuf>, name: &str) -> FileLocalStore {
    FileLocalStore::new(home_dir(home, name))
}

fn load_identity(store: &FileLocalStore) -> Result<Identity, String> {
    store
        .load_identity()?
        .ok_or_else(|| "no identity; run `yakr init` first".into())
}

fn b64encode(data: &[u8]) -> String {
    URL_SAFE.encode(data).trim_end_matches('=').to_string()
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Init { name, home, force } => {
            let store = store_at(home, &name);
            if store.identity_path().exists() && !force {
                return Err(format!(
                    "identity already exists at {}",
                    store.identity_path().display()
                ));
            }
            let identity = Identity::generate(&name, true);
            store.save_identity(&identity)?;
            println!("Initialized identity '{name}' at {}", store.root.display());
        }
        Commands::Show { home } => {
            let store = store_at(home, &default_name()?);
            let identity = load_identity(&store)?;
            println!("name: {}", identity.name);
            println!("device_id: {}", identity.device_id());
        }
        Commands::ExportPublic { home } => {
            let store = store_at(home, &default_name()?);
            let _ = load_identity(&store)?;
            let path = store.root.join("public.json");
            println!("{}", std::fs::read_to_string(path).map_err(|e| e.to_string())?);
        }
        Commands::Send {
            contact,
            message,
            relay,
            home,
        } => {
            let store = store_at(home, &default_name()?);
            let identity = load_identity(&store)?;
            let mut contact_rec = store
                .get_contact(&contact)?
                .ok_or_else(|| format!("contact not found: {contact}"))?;
            let mut session = Session::new(identity, contact_rec).map_err(|e| e.to_string())?;
            let encrypted = session.encrypt_text(&message).map_err(|e| e.to_string())?;
            let relay_json = encrypted.outer_blob.to_relay_json();
            post_blob(&relay, &relay_json)?;
            store.save_contact(&session.into_contact())?;
            println!("sent to {contact} (msg_id={})", encrypted.msg_id);
        }
        Commands::Fetch {
            contact,
            relay,
            home,
        } => {
            let store = store_at(home, &default_name()?);
            let identity = load_identity(&store)?;
            let mut contact_rec = store
                .get_contact(&contact)?
                .ok_or_else(|| format!("contact not found: {contact}"))?;
            let deriver = yakr_core::mailbox::MailboxTagDeriver::from_master(
                &contact_rec.master_secret,
                &format!("{}->{}", contact, identity.name),
                contact_rec.mailbox_epoch_secs,
            );
            let direction = format!("{}->{}", contact, identity.name);
            let tags = deriver.candidate_epochs(&direction, 2);
            let client = Client::new();
            let mut found = 0usize;
            for tag in tags {
                let url = format!(
                    "{}/v1/blobs/{}",
                    relay.trim_end_matches('/'),
                    b64encode(&tag.tag)
                );
                let blobs: Vec<RelayBlobJson> = client
                    .get(url)
                    .send()
                    .map_err(|e| e.to_string())?
                    .error_for_status()
                    .map_err(|e| e.to_string())?
                    .json()
                    .map_err(|e| e.to_string())?;
                let mut session =
                    Session::new(identity.clone(), contact_rec.clone()).map_err(|e| e.to_string())?;
                for blob_json in blobs {
                    let outer = OuterBlob::from_relay_json(&blob_json)?;
                    match session.decrypt_outer(&outer) {
                        Ok(inner) => {
                            println!(
                                "from {} seq={} body={:?}",
                                contact,
                                inner.seq,
                                inner.body
                            );
                            found += 1;
                        }
                        Err(_) => continue,
                    }
                }
                contact_rec = session.into_contact();
            }
            store.save_contact(&contact_rec)?;
            println!("fetched {found} message(s) from {contact}");
        }
    }
    Ok(())
}

fn default_name() -> Result<String, String> {
    std::env::var("YAKR_NAME").or_else(|_| Err("set --name on init or YAKR_NAME".into()))
}

fn post_blob(relay: &str, blob: &RelayBlobJson) -> Result<(), String> {
    let client = Client::new();
    client
        .post(format!("{}/v1/blobs", relay.trim_end_matches('/')))
        .json(blob)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(dead_code)]
fn pair_demo() {
    let alice = Identity::generate("alice", false);
    let bob = Identity::generate("bob", false);
    let invite = create_invite(&alice, "http://test", 60_000, false).unwrap();
    let (request, secrets) = build_pairing_request(&bob, &invite, "bob").unwrap();
    let (ephemeral, _) = x25519_generate_keypair();
    let (response, _) =
        inviter_complete_pairing(&alice, &invite, &request, ephemeral).unwrap();
    let _bob_contact = joiner_complete_pairing(&bob, &invite, &request, &secrets, &response).unwrap();
}
