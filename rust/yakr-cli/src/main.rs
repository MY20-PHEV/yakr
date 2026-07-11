use std::fs;
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
    Identity,
};
use yakr_crypto::x25519_generate_keypair;

mod interop;

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
        #[arg(long)]
        classical: bool,
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
    Interop {
        #[command(subcommand)]
        command: InteropCommands,
    },
}

#[derive(Subcommand)]
enum InteropCommands {
    Init {
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = true)]
        classical: bool,
    },
    CreateInvite {
        #[arg(long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        rendezvous: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = true)]
        classical: bool,
    },
    JoinerRequest {
        #[arg(long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        invite: PathBuf,
        #[arg(long)]
        out_request: PathBuf,
        #[arg(long)]
        out_secrets: PathBuf,
    },
    JoinerComplete {
        #[arg(long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        invite: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        secrets: PathBuf,
        #[arg(long)]
        response: PathBuf,
    },
    InviterComplete {
        #[arg(long)]
        name: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        invite: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out_response: PathBuf,
    },
}

pub(crate) fn home_dir(home: Option<PathBuf>, name: &str) -> PathBuf {
    home.unwrap_or_else(|| {
        std::env::var("YAKR_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_home().join(".yakr").join(name))
    })
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn store_at(home: Option<PathBuf>, name: &str) -> FileLocalStore {
    FileLocalStore::new(home_dir(home, name))
}

pub(crate) fn load_identity(store: &FileLocalStore) -> Result<Identity, String> {
    store
        .load_identity()?
        .ok_or_else(|| "no identity; run `yakr init` first".into())
}

pub(crate) fn b64encode(data: &[u8]) -> String {
    URL_SAFE.encode(data).trim_end_matches('=').to_string()
}

pub(crate) fn b64decode_str(value: &str) -> Result<Vec<u8>, String> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE
        .decode(padded)
        .map_err(|e| e.to_string())
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
        Commands::Init {
            name,
            home,
            force,
            classical,
        } => interop::run_init(&name, home, force, classical),
        Commands::Show { home } => {
            let store = store_at(home, &default_name()?);
            let identity = load_identity(&store)?;
            println!("name: {}", identity.name);
            println!("device_id: {}", identity.device_id());
            Ok(())
        }
        Commands::ExportPublic { home } => {
            let store = store_at(home, &default_name()?);
            let _ = load_identity(&store)?;
            let path = store.root.join("public.json");
            println!("{}", fs::read_to_string(path).map_err(|e| e.to_string())?);
            Ok(())
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
            Ok(())
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
            Ok(())
        }
        Commands::Interop { command } => match command {
            InteropCommands::Init {
                name,
                home,
                force,
                classical,
            } => interop::run_init(&name, home, force, classical),
            InteropCommands::CreateInvite {
                name,
                home,
                rendezvous,
                out,
                classical,
            } => interop::run_create_invite(home, &name, &rendezvous, &out, classical),
            InteropCommands::JoinerRequest {
                name,
                home,
                invite,
                out_request,
                out_secrets,
            } => interop::run_joiner_request(home, &name, &invite, &out_request, &out_secrets),
            InteropCommands::JoinerComplete {
                name,
                home,
                invite,
                request,
                secrets,
                response,
            } => interop::run_joiner_complete(
                home,
                &name,
                &invite,
                &request,
                &secrets,
                &response,
            ),
            InteropCommands::InviterComplete {
                name,
                home,
                invite,
                request,
                out_response,
            } => interop::run_inviter_complete(home, &name, &invite, &request, &out_response),
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_demo() {
        let alice = Identity::generate("alice", false);
        let bob = Identity::generate("bob", false);
        let invite = create_invite(&alice, "http://test", 60_000, false).unwrap();
        let (request, secrets) = build_pairing_request(&bob, &invite, "bob").unwrap();
        let (ephemeral, _) = x25519_generate_keypair();
        let (response, _) =
            inviter_complete_pairing(&alice, &invite, &request, ephemeral, None).unwrap();
        let _bob_contact =
            joiner_complete_pairing(&bob, &invite, &request, &secrets, &response).unwrap();
    }
}
