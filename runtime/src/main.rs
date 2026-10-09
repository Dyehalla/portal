fn main() {
    let path = std::env::var_os("PORTAL_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "portal.json".into());
    if let Err(error) = portal_runtime::load_config(&path).and_then(portal_runtime::run) {
        eprintln!("portal-runtime: {error}");
        std::process::exit(1);
    }
}
