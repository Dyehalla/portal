use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use portal_files::download;

// Run the selected file-service command and return failures with a nonzero exit status.
#[tokio::main]
async fn main() {
    if let Err(error) = entry().await {
        eprintln!("portal-files: {error}");
        std::process::exit(1);
    }
}

// Parse the top-level command and dispatch to the server or download client.
async fn entry() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };
    match command {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "download" => download_command(&args[1..]).await,
        "smb-list" => smb_command(&args[1..], false).await,
        "smb-connect" => smb_command(&args[1..], true).await,
        other => Err(format!(
            "unknown command `{other}`; use `portal-files help`"
        )),
    }
}

// Print the peer-facing file service commands and their required network settings.
fn print_usage() {
    println!(
        "\
portal-files — peer file sharing over gRPC, HTTP and SMB

Commands:
  portal-files download --grpc http://PEER_IP:PORT --path RELATIVE_PATH --output FILE
  portal-files smb-list --grpc http://PEER_IP:PORT
  portal-files smb-connect --grpc http://PEER_IP:PORT --share NAME

File sharing is hosted by portal-runtime. Authorization uses the caller's
WireGuard tunnel IP; HTTP tickets are short-lived and single-use."
    );
}

// Request a download ticket over gRPC and save the HTTP stream to the requested destination.
async fn download_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args)?;
    validate_options(&options, &["grpc", "path", "output"], &[])?;
    download(
        required(&options, "grpc")?,
        required(&options, "path")?,
        &PathBuf::from(required(&options, "output")?),
    )
    .await
}

// Parse `--name value` pairs while preserving repeated permission options.
fn parse_options(args: &[String]) -> Result<HashMap<String, Vec<String>>, String> {
    let mut options = HashMap::<String, Vec<String>>::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index]
            .strip_prefix("--")
            .ok_or_else(|| format!("expected an option, got `{}`", args[index]))?;
        if option.is_empty() {
            return Err("empty option name".into());
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| format!("option --{option} requires a value"))?;
        options
            .entry(option.to_owned())
            .or_default()
            .push(value.clone());
        index += 2;
    }
    Ok(options)
}

// Reject unsupported options and duplicates outside the permission-list flag.
fn validate_options(
    options: &HashMap<String, Vec<String>>,
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<(), String> {
    for (name, values) in options {
        if !allowed.contains(&name.as_str()) {
            return Err(format!("unknown option --{name}"));
        }
        if values.len() > 1 && !repeatable.contains(&name.as_str()) {
            return Err(format!("option --{name} may only be specified once"));
        }
    }
    Ok(())
}

// Return the first value for a required option with a useful missing-flag error.
fn required<'a>(options: &'a HashMap<String, Vec<String>>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option --{name}"))
}

async fn smb_command(args: &[String], open: bool) -> Result<(), String> {
    let options = parse_options(args)?;
    validate_options(
        &options,
        if open { &["grpc", "share"] } else { &["grpc"] },
        &[],
    )?;
    let grpc = required(&options, "grpc")?;
    if open {
        return portal_files::open_smb(grpc, required(&options, "share")?).await;
    }
    for share in portal_files::list_shares(grpc).await? {
        let host = share
            .host
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid advertised SMB host")?;
        let address = std::net::SocketAddr::new(
            host,
            u16::try_from(share.port).map_err(|_| "invalid advertised SMB port")?,
        );
        println!(
            "{} smb://{}/{} {}",
            share.name,
            address,
            share.name,
            if share.read_only {
                "read-only"
            } else {
                "read-write"
            }
        );
    }
    Ok(())
}
