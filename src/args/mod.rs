use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, Default, Parser)]
#[command(author, version = "0.2.0", about, long_about = None)]
pub struct Args {
    /// work address, accept ip, subnet mask, ip segment./n
    #[arg(short, long)]
    pub address: String,
    /// whether to ping before work.
    #[arg(long)]
    pub ping: bool,
    /// work port, accept port, port range.
    #[arg(short, long)]
    pub ports: Option<String>,
}
