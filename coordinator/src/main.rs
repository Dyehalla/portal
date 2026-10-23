use portal_coordinator::{Coordinator, config::Config};
use std::{path::Path, time::Duration};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("portal-coordinator: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!(
            "Usage: portal-coordinator --config PATH\n\nStarts an HTTPS coordinator; initializes a network and admin account on first start.\nThe administrator token is saved in STATE_DIR/admin.token."
        );
        return Ok(());
    }
    if args.len() != 2 || args[0] != "--config" {
        return Err("usage: portal-coordinator --config PATH".into());
    }
    let config = Config::load(Path::new(&args[1]))?;
    let token_path = config.state_dir.join("admin.token");
    let coordinator = Coordinator::open(config).await?;
    let handle = axum_server::Handle::new();
    let server = coordinator.serve(handle.clone());
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result.map_err(|e| e.to_string()),
        listening = handle.listening() => {
            let listening = listening.ok_or("HTTPS listener did not start")?;
            println!("READY https={} admin_token_file={}", listening, token_path.display());
        }
    }
    tokio::select! {
        result = &mut server => result.map_err(|e| e.to_string()),
        result = shutdown_signal() => {
            result?;
            handle.graceful_shutdown(Some(Duration::from_secs(3)));
            server.await.map_err(|e| e.to_string())
        }
    }
}

async fn shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| format!("could not install termination handler: {e}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|e| e.to_string()),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())
}
