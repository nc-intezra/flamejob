//! fj — the flamejob command-line client. Thin wrapper over flamejob-client.
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use flamejob_api::{HashlistCreate, JobConfig, JobCreate, LoginRequest};
use flamejob_client::Client;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "fj", about = "flamejob CLI", version)]
struct Cli {
    #[arg(
        long,
        env = "FJ_SERVER",
        default_value = "http://localhost:8443",
        global = true
    )]
    server: String,
    #[arg(long, global = true, help = "emit raw JSON")]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Authenticate and cache a token
    Login {
        #[arg(long)]
        user: String,
        #[arg(long)]
        password: String,
    },
    /// Show the current identity and roles
    Whoami,
    /// Forget the cached token
    Logout,
    /// Job queue operations
    Job {
        #[command(subcommand)]
        cmd: JobCmd,
    },
    /// Hashlist operations
    Hashlist {
        #[command(subcommand)]
        cmd: HashlistCmd,
    },
}

#[derive(Subcommand)]
enum JobCmd {
    Ls,
    Show {
        id: Uuid,
    },
    Submit {
        #[arg(long)]
        hashlist: Uuid,
        #[arg(short = 'a', long, default_value_t = 0)]
        attack_mode: i16,
        #[arg(long)]
        name: String,
        #[arg(long)]
        wordlist: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        priority: i32,
    },
    Pause {
        id: Uuid,
    },
    Resume {
        id: Uuid,
    },
    Cancel {
        id: Uuid,
    },
    Prio {
        id: Uuid,
        priority: i32,
    },
}

#[derive(Subcommand)]
enum HashlistCmd {
    Ls,
    Create {
        #[arg(long)]
        name: String,
        #[arg(short = 'm', long)]
        hash_type: i32,
    },
    /// Show decrypted cracked results (needs ViewPlaintext)
    Cracked {
        id: Uuid,
    },
}

fn token_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/flamejob/token")
}

fn load_token() -> Option<String> {
    fs::read_to_string(token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

fn save_token(token: &str) -> Result<()> {
    let path = token_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, token)?;
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new(&cli.server).with_token(load_token());

    match cli.cmd {
        Cmd::Login { user, password } => {
            let resp = client
                .login(&LoginRequest {
                    username: user,
                    password,
                })
                .await?;
            save_token(&resp.token).context("saving token")?;
            println!("logged in; roles: {:?}", resp.roles);
        }
        Cmd::Whoami => {
            let me = client.me().await?;
            if cli.json {
                print_json(&me)?;
            } else {
                println!("{} {:?}", me.username, me.roles);
            }
        }
        Cmd::Logout => {
            let _ = fs::remove_file(token_path());
            println!("logged out");
        }
        Cmd::Job { cmd } => match cmd {
            JobCmd::Ls => {
                let jobs = client.list_jobs().await?;
                if cli.json {
                    print_json(&jobs)?;
                } else {
                    for j in &jobs {
                        println!("{}  {:<24}  {:?}  p{}", j.id, j.name, j.state, j.priority);
                    }
                }
            }
            JobCmd::Show { id } => print_json(&client.get_job(id).await?)?,
            JobCmd::Submit {
                hashlist,
                attack_mode,
                name,
                wordlist,
                priority,
            } => {
                let req = JobCreate {
                    name,
                    hashlist_id: hashlist,
                    attack_mode,
                    priority: Some(priority),
                    config: JobConfig {
                        wordlist_file_id: wordlist,
                        rule_file_ids: vec![],
                        mask: None,
                        extra_args: vec![],
                    },
                };
                let job = client.create_job(&req).await?;
                if cli.json {
                    print_json(&job)?;
                } else {
                    println!("submitted {}", job.id);
                }
            }
            JobCmd::Pause { id } => client.job_action(id, "pause").await?,
            JobCmd::Resume { id } => client.job_action(id, "resume").await?,
            JobCmd::Cancel { id } => client.job_action(id, "cancel").await?,
            JobCmd::Prio { id, priority } => client.set_priority(id, priority).await?,
        },
        Cmd::Hashlist { cmd } => match cmd {
            HashlistCmd::Ls => {
                let lists = client.list_hashlists().await?;
                if cli.json {
                    print_json(&lists)?;
                } else {
                    for h in &lists {
                        println!(
                            "{}  {:<24}  -m {}  {}/{}",
                            h.id, h.name, h.hash_type, h.cracked, h.total
                        );
                    }
                }
            }
            HashlistCmd::Create { name, hash_type } => {
                let hl = client
                    .create_hashlist(&HashlistCreate { name, hash_type })
                    .await?;
                if cli.json {
                    print_json(&hl)?;
                } else {
                    println!("created {}", hl.id);
                }
            }
            HashlistCmd::Cracked { id } => {
                let cracked = client.list_cracked(id).await?;
                if cli.json {
                    print_json(&cracked)?;
                } else {
                    for c in &cracked {
                        println!("{}  ->  {}", c.hash, c.plain);
                    }
                }
            }
        },
    }
    Ok(())
}
