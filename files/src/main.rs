use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

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
        "resources" | "ls" | "stat" => browse_command(command, &args[1..]).await,
        other => Err(format!(
            "unknown command `{other}`; use `portal-files help`"
        )),
    }
}

// Print the peer-facing file service commands and their required network settings.
fn print_usage() {
    println!(
        "\
portal-files — peer file sharing over HTTP

Commands:
  portal-files download --peer PUBLIC_KEY_HEX [--port 8080] --path RELATIVE_PATH --output FILE
  portal-files resources --peer PUBLIC_KEY_HEX [--port 8080]
  portal-files ls --peer PUBLIC_KEY_HEX [--port 8080] [--path DIR] [--offset N] [--limit N]
  portal-files stat --peer PUBLIC_KEY_HEX [--port 8080] --path PATH

Requests go through the local runtime (--api http://127.0.0.1:51821, --api-token-file PATH).
Peer IPs are virtual addresses inside its userspace stack; HTTP tickets are short-lived and single-use."
    );
}

fn default_token_file() -> std::path::PathBuf {
    #[cfg(unix)]
    let name = format!("portal-{}.token", unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let name = "portal.token";
    std::env::temp_dir().join(name)
}

fn api_options(
    options: &HashMap<String, Vec<String>>,
) -> Result<(String, zeroize::Zeroizing<String>, serde_json::Value), String> {
    let api = options
        .get("api")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:51821".into());
    let token_path = options
        .get("api-token-file")
        .and_then(|v| v.first())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_token_file());
    let token = zeroize::Zeroizing::new(
        std::fs::read_to_string(&token_path)
            .map_err(|e| format!("could not read {}: {e}", token_path.display()))?
            .trim()
            .to_owned(),
    );
    let port: u16 = options
        .get("port")
        .and_then(|v| v.first())
        .map(|v| v.parse().map_err(|_| "invalid --port".to_owned()))
        .unwrap_or(Ok(8080))?;
    let mut request = serde_json::json!({"peer":required(options,"peer")?,"port":port});
    if let Some(ip) = options.get("tunnel-ip").and_then(|v| v.first()) {
        request["tunnel_ip"] = serde_json::Value::String(ip.clone());
    }
    Ok((api, token, request))
}
async fn download_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args)?;
    validate_options(
        &options,
        &[
            "api",
            "api-token-file",
            "peer",
            "port",
            "tunnel-ip",
            "path",
            "output",
        ],
        &[],
    )?;
    let (api, token, mut request) = api_options(&options)?;
    let path = required(&options, "path")?;
    request["path"] = path.into();
    portal_files::local_download(
        &api,
        &token,
        &request,
        path,
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

async fn browse_command(command: &str, args: &[String]) -> Result<(), String> {
    let options = parse_options(args)?;
    let allowed: &[&str] = match command {
        "resources" => &["api", "api-token-file", "peer", "port", "tunnel-ip"],
        "stat" => &["api", "api-token-file", "peer", "port", "tunnel-ip", "path"],
        _ => &[
            "api",
            "api-token-file",
            "peer",
            "port",
            "tunnel-ip",
            "path",
            "offset",
            "limit",
        ],
    };
    validate_options(&options, allowed, &[])?;
    let (api, token, mut request) = api_options(&options)?;
    let operation = match command {
        "resources" => "resources",
        "stat" => "metadata",
        _ => "list",
    };
    if operation != "resources" {
        request["path"] = options
            .get("path")
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or("")
            .into();
    }
    if operation == "list" {
        for (name, default) in [("offset", 0usize), ("limit", 100usize)] {
            let number = options
                .get(name)
                .and_then(|v| v.first())
                .map(|v| v.parse::<usize>().map_err(|_| format!("invalid --{name}")))
                .unwrap_or(Ok(default))?;
            request[name] = number.into();
        }
    }
    let value: serde_json::Value =
        portal_files::local_json(&api, &token, operation, &request).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
    );
    Ok(())
}
