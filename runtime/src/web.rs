/// Embed the prototype so a runtime binary can serve the UI without a separate web server.
pub(crate) fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" => Some((
            "text/html; charset=utf-8",
            include_str!("../../web/index.html"),
        )),
        "/app.js" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../web/app.js"),
        )),
        "/styles.css" => Some((
            "text/css; charset=utf-8",
            include_str!("../../web/styles.css"),
        )),
        "/favicon.svg" => Some(("image/svg+xml", include_str!("../../web/favicon.svg"))),
        _ => None,
    }
}
