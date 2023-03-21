use crate::scanner::Scanner;
use crate::utils::address::ParseAddress;
use crate::utils::port::resolve_ports_or_all;
use clap::Parser;
use colorful::{Color, Colorful};
use std::io;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter};

mod args;
mod scanner;
mod utils;

#[tokio::main]
async fn main() {
    let file_appender = tracing_appender::rolling::daily("./log", "magic.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(fmt::Layer::new().with_writer(io::stdout))
        .with(fmt::Layer::new().with_writer(non_blocking));
    tracing::subscriber::set_global_default(subscriber).expect("Unable to set a global subscriber");
    print_banner();

    let args = args::Args::parse();
    let address = args.address;
    let parse_result = ParseAddress::resolve_ips(address.as_str()).await;
    if !parse_result.invalid_address.is_empty() {
        tracing::warn!("invalid address: {:?}", parse_result.invalid_address);
    }
    tracing::info!("address: {:?}", &parse_result.valid_address);
    if parse_result.valid_address.is_empty() {
        tracing::warn!("there is no address to perform the task, please reenter.");
        return;
    }
    let ports = resolve_ports_or_all(args.ports);
    tracing::info!("ports size: {:?}", ports.len());

    let valid_address = parse_result.valid_address;
    let scanner = Scanner::new(
        Vec::from_iter(valid_address),
        Vec::from_iter(ports),
        4500,
        args.ping,
    )
    .await;
    scanner.run().await;
    tracing::info!("running end.");
}

pub fn print_banner() {
    tracing::info!(
        "{}",
        r#" __  __          _____ _____ _____  _____  _____          _   _ _   _ ______ _____  "#
            .gradient(Color::LightBlue)
    );
    tracing::info!(
        "{}",
        r#"|  \/  |   /\   / ____|_   _/ ____|/ ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ "#
            .gradient(Color::LightBlue)
    );
    tracing::info!(
        "{}",
        r#"| \  / |  /  \ | |  __  | || |    | (___ | |       /  \  |  \| |  \| | |__  | |__) |"#
            .gradient(Color::LightBlue)
    );
    tracing::info!(
        "{}",
        r#"| |\/| | / /\ \| | |_ | | || |     \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / "#
            .gradient(Color::LightBlue)
    );
    tracing::info!(
        "{}",
        r#"| |  | |/ ____ \ |__| |_| || |____ ____) | |____ / ____ \| |\  | |\  | |____| | \ \ "#
            .gradient(Color::LightBlue)
    );
    tracing::info!(
        "{}",
        r#"|_|  |_/_/    \_\_____|_____\_____|_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\"#
            .gradient(Color::LightBlue)
    );
}
