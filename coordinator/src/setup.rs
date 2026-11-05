//! Interactive bootstrap; normal service startup never reads stdin or prints secrets.
use portal_coordinator::config::{Config, StunConfig, TlsConfig};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use zeroize::Zeroizing;

const UNIT: &str = "portal-coordinator.service";
const UNIT_PATH: &str = "/etc/systemd/system/portal-coordinator.service";
const BINARY_PATH: &str = "/usr/local/lib/portal-coordinator/portal-coordinator";
const SERVICE_STATE_ROOT: &str = "/var/lib/portal-coordinator";
// DynamicUser may make StateDirectory itself a symlink. The store requires
// its final directory to be a real private directory, so use a child.
const SERVICE_STATE: &str = "/var/lib/portal-coordinator/data";
const SERVICE_CREDENTIALS: &str = "/run/credentials/portal-coordinator.service";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Service,
    Foreground,
    Save,
}

struct Prompt<R, W> {
    input: R,
    output: W,
}
impl<R: BufRead, W: Write> Prompt<R, W> {
    fn say(&mut self, message: impl std::fmt::Display) -> Result<(), String> {
        writeln!(self.output, "{message}").map_err(|e| e.to_string())
    }
    fn ask(&mut self, label: &str, default: &str) -> Result<String, String> {
        write!(self.output, "{label} [{default}]: ").map_err(|e| e.to_string())?;
        self.output.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if self.input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("Ввод завершён. Настройка прервана.".into());
        }
        let value = line.trim();
        Ok(if value.is_empty() { default } else { value }.to_owned())
    }
    fn validated<T>(
        &mut self,
        label: &str,
        default: &str,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> Result<T, String> {
        loop {
            let value = self.ask(label, default)?;
            match parse(&value) {
                Ok(value) => return Ok(value),
                Err(error) => self.say(error)?,
            }
        }
    }
    fn yes(&mut self, label: &str) -> Result<bool, String> {
        self.validated(label, "нет", |value| {
            match value.to_lowercase().as_str() {
                "y" | "yes" | "д" | "да" => Ok(true),
                "n" | "no" | "н" | "нет" => Ok(false),
                _ => Err("Введите «да» или «нет».".into()),
            }
        })
    }
}

pub async fn run(
    args: &[String],
) -> Result<Option<(Config, portal_coordinator::Coordinator)>, String> {
    let directory = match args {
        [] => None,
        [flag, path] if flag == "--dir" => Some(PathBuf::from(path)),
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "portal-coordinator setup [--dir PATH]\nМастер новой установки. Существующие файлы не перезаписываются."
            );
            return Ok(None);
        }
        _ => return Err("usage: portal-coordinator setup [--dir PATH]".into()),
    };
    let mut prompt = Prompt {
        input: io::stdin().lock(),
        output: io::stdout(),
    };
    let Some(plan) = collect(&mut prompt, directory)? else {
        return Ok(None);
    };
    let config_path = save(&plan).await?;
    prompt.say(format!(
        "\nКонфигурация сохранена: {}",
        config_path.display()
    ))?;
    prompt.say(format!("Адрес для клиентов: {}", plan.origin()))?;
    prompt.say(format!(
        "Откройте TCP/{} и UDP/{} на сервере и в NAT. Мастер не меняет firewall и DNS.",
        plan.config.listen.port(),
        plan.config.listen.port()
    ))?;
    if plan.self_signed {
        prompt.say(format!(
            "В панели Portal выберите доверенный сертификат: {}",
            plan.config.tls.cert_file.display()
        ))?;
    }
    match plan.mode {
        Mode::Service => {
            install_service(&plan)?;
            prompt.say("Служба установлена и запущена. Автозапуск включён.")?;
            prompt.say(format!(
                "Состояние: systemctl status {UNIT}\nЖурнал: journalctl -u {UNIT}"
            ))?;
            prompt.say(format!(
                "Токен admin появится в {SERVICE_STATE}/admin.token при первом успешном запуске."
            ))?;
            if prompt.yes("Показать токен admin сейчас? Он даёт вход в аккаунт администратора")?
            {
                // StateDirectory may be a symlink managed by systemd DynamicUser.
                show_admin(&mut prompt, Path::new(SERVICE_STATE))?;
                prompt.say("Сохраните токен для входа через приложение Portal.")?;
            }
            Ok(None)
        }
        Mode::Foreground => {
            prompt.say(format!(
                "Запускаем сервер. Ctrl+C — остановка. Токен admin: {}",
                plan.config.state_dir.join("admin.token").display()
            ))?;
            let show_token = prompt.yes("Показать токен admin после создания сети?")?;
            let coordinator = portal_coordinator::Coordinator::open(plan.config.clone()).await?;
            if show_token {
                show_admin(&mut prompt, &plan.config.state_dir)?;
            }
            Ok(Some((plan.config, coordinator)))
        }
        Mode::Save => {
            prompt.say(format!(
                "Запуск:\n{} --config {}",
                shell_quote(&std::env::current_exe().map_err(|e| e.to_string())?),
                shell_quote(&config_path)
            ))?;
            prompt.say(format!(
                "После первого запуска токен admin будет в {}",
                plan.config.state_dir.join("admin.token").display()
            ))?;
            Ok(None)
        }
    }
}

struct Plan {
    mode: Mode,
    directory: PathBuf,
    host: String,
    config: Config,
    cert: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    self_signed: bool,
}
impl Plan {
    fn origin(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.config.listen.port() == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.config.listen.port())
        }
    }
}

fn collect<R: BufRead, W: Write>(
    prompt: &mut Prompt<R, W>,
    directory: Option<PathBuf>,
) -> Result<Option<Plan>, String> {
    prompt.say("Portal — установка координатора\n1 — служба systemd с автозапуском (нужен root)\n2 — запуск в текущем терминале\n3 — только сохранить конфигурацию")?;
    let mode = prompt.validated("Способ запуска", "2", |value| match value {
        "1" => Ok(Mode::Service),
        "2" => Ok(Mode::Foreground),
        "3" => Ok(Mode::Save),
        _ => Err("Выберите 1, 2 или 3.".into()),
    })?;
    if mode == Mode::Service {
        check_service_environment()?;
    }
    let directory = absolute(&match directory {
        Some(path) => path,
        None => PathBuf::from(prompt.ask(
            "Новый каталог настройки",
            if mode == Mode::Service {
                "/etc/portal-coordinator"
            } else {
                "coordinator-config"
            },
        )?),
    })?;
    if fs::symlink_metadata(&directory).is_ok() {
        return Err(format!(
            "Каталог {} уже существует. Для запуска используйте --config; для новой установки выберите другой каталог. Состояние и токены сохранены.",
            directory.display()
        ));
    }
    let host = prompt.validated(
        "DNS-имя или IP для подключения клиентов, без схемы и порта",
        "localhost",
        parse_host,
    )?;
    let default_listen = match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => SocketAddr::new(ip, 8443).to_string(),
        Ok(IpAddr::V6(_)) => "[::]:8443".into(),
        _ if host == "localhost" => "127.0.0.1:8443".into(),
        _ => "0.0.0.0:8443".into(),
    };
    let listen = prompt.validated(
        "Адрес прослушивания HTTPS и STUN (IP:порт)",
        &default_listen,
        |value| {
            let address: SocketAddr = value
                .parse()
                .map_err(|_| "Введите IP:порт, например 0.0.0.0:8443 или [::]:8443".to_owned())?;
            if address.port() == 0 || address.ip().is_multicast() {
                return Err("Нужен постоянный порт 1–65535 и unicast/wildcard адрес.".into());
            }
            Ok(address)
        },
    )?;
    if mode == Mode::Service && listen.port() < 1024 {
        prompt.say("Службе будет разрешено привязывать системный порт; процесс работает с отдельной динамической учётной записью.")?;
    }
    prompt.say("TLS:\n1 — готовые PEM-сертификат и приватный ключ\n2 — создать самоподписанный сертификат на 365 дней (клиенты доверяют ему явно)")?;
    let self_signed =
        prompt.validated("Способ настройки TLS", "2", |value| match value {
            "1" => Ok(false),
            "2" => Ok(true),
            _ => Err("Выберите 1 или 2.".into()),
        })?;
    let (cert, key) = if self_signed {
        let mut params =
            rcgen::CertificateParams::new(vec![host.clone()]).map_err(|e| e.to_string())?;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, &host);
        let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        (
            cert.pem().into_bytes(),
            Zeroizing::new(key.serialize_pem().into_bytes()),
        )
    } else {
        prompt.say("Сертификат должен соответствовать указанному имени/IP. PEM-цепочка начинается с сертификата сервера. Автоматическое продление не настраивается.")?;
        let cert = prompt.validated("Путь к PEM-сертификату/цепочке", "", read_pem)?;
        let key = Zeroizing::new(prompt.validated(
            "Путь к PEM-приватному ключу (без пароля)",
            "",
            read_pem,
        )?);
        (cert, key)
    };
    let mut config = Config {
        listen,
        state_dir: if mode == Mode::Service {
            PathBuf::from(SERVICE_STATE)
        } else {
            directory.join("state")
        },
        ipv4_network: "10.77.0.0/16".parse().unwrap(),
        ipv6_network: "fd77:706f:7274::/64".parse().unwrap(),
        lease_seconds: 300,
        tls: TlsConfig {
            cert_file: directory.join("cert.pem"),
            key_file: directory.join("key.pem"),
        },
        stun: StunConfig::default(),
    };
    if prompt
        .yes("Изменить адресные пулы VPN (по умолчанию 10.77.0.0/16 и fd77:706f:7274::/64)?")?
    {
        config.ipv4_network = prompt.validated(
            "Приватная IPv4-подсеть /16–/30",
            "10.77.0.0/16",
            |value| {
                let mut candidate = config.clone();
                candidate.ipv4_network = value
                    .parse()
                    .map_err(|_| "Неверная IPv4-подсеть".to_owned())?;
                candidate.validate()?;
                Ok(candidate.ipv4_network)
            },
        )?;
        config.ipv6_network = prompt.validated(
            "ULA IPv6-подсеть /64",
            "fd77:706f:7274::/64",
            |value| {
                let mut candidate = config.clone();
                candidate.ipv6_network = value
                    .parse()
                    .map_err(|_| "Неверная IPv6-подсеть".to_owned())?;
                candidate.validate()?;
                Ok(candidate.ipv6_network)
            },
        )?;
    }
    config.validate()?;
    let plan = Plan {
        mode,
        directory,
        host,
        config,
        cert,
        key,
        self_signed,
    };
    prompt.say(format!("\nБудет создана новая установка:\n  Адрес: {}\n  Слушаем: {} (TCP + UDP)\n  Конфигурация: {}\n  Данные: {}\n  Пулы: {}, {}", plan.origin(), plan.config.listen, plan.directory.display(), plan.config.state_dir.display(), plan.config.ipv4_network, plan.config.ipv6_network))?;
    if mode == Mode::Service {
        prompt.say(format!(
            "  Бинарник: {BINARY_PATH}\n  Служба: {UNIT_PATH}\n  Автозапуск: включён"
        ))?;
    }
    if !prompt.yes("Создать установку с этими параметрами?")? {
        prompt.say("Отменено. Файлы не создавались.")?;
        return Ok(None);
    }
    Ok(Some(plan))
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("Укажите непустой путь".into());
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("Путь не должен содержать '..'.".into());
    }
    if path
        .to_str()
        .is_none_or(|value| value.chars().any(char::is_control))
    {
        return Err("Путь должен быть UTF-8 и не содержать управляющих символов.".into());
    }
    Ok(path)
}
fn parse_host(value: &str) -> Result<String, String> {
    let host = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        {
            return Err("Укажите адрес, доступный клиентам, а не wildcard или multicast.".into());
        }
        return Ok(ip.to_string());
    }
    if host.contains(['/', ':', '?', '#', '@', '\\', '%'])
        || host.is_empty()
        || host.chars().any(char::is_whitespace)
    {
        return Err("Нужны только DNS-имя или IP, без схемы, порта и пути.".into());
    }
    let host = url::Host::parse(host)
        .map_err(|_| "Неверное DNS-имя".to_owned())?
        .to_string();
    // URL host parsing also accepts alternate IPv4 spellings (e.g. 0x0).
    // Apply address restrictions after normalization as well.
    if host.parse::<IpAddr>().is_ok() {
        return parse_host(&host);
    }
    if host.len() > 253
        || host.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("Неверное DNS-имя".into());
    }
    Ok(host)
}
fn read_pem(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|e| format!("Не удалось прочитать PEM-файл: {e}"))?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("PEM-файл должен быть не больше 1 МиБ.".into());
    }
    Ok(bytes)
}

async fn save(plan: &Plan) -> Result<PathBuf, String> {
    // Validate certificate, key, hostname and validity before creating any files.
    validate_tls(&plan.host, &plan.cert, &plan.key).await?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&plan.directory).map_err(|e| {
        format!(
            "Не удалось создать новый каталог {}: {e}",
            plan.directory.display()
        )
    })?;
    let config_path = plan.directory.join("config.json");
    let result = (|| {
        write_new(&plan.config.tls.cert_file, &plan.cert, 0o600)?;
        write_new(&plan.config.tls.key_file, &plan.key, 0o600)?;
        write_new(
            &config_path,
            &serde_json::to_vec_pretty(&plan.config).map_err(|e| e.to_string())?,
            0o600,
        )?;
        fs::File::open(&plan.directory)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(config_path.clone())
    })();
    // On failure retain files rather than risk removing a path changed by another process.
    result.map_err(|error: String| {
        format!(
            "{error}. Частичная настройка сохранена в {}.",
            plan.directory.display()
        )
    })
}
async fn validate_tls(host: &str, cert: &[u8], key: &[u8]) -> Result<(), String> {
    use rustls::{
        client::danger::ServerCertVerifier,
        pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    };
    axum_server::tls_rustls::RustlsConfig::from_pem(cert.to_vec(), key.to_vec())
        .await
        .map_err(|e| {
            format!(
                "Сертификат и ключ TLS не подходят друг к другу или имеют неверный PEM-формат: {e}"
            )
        })?;
    let chain: Vec<_> = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let leaf = chain.first().ok_or("PEM-файл не содержит сертификат")?;
    let roots = trusted_chain(cert)?;
    // Trust here is explicit to validate the provided chain, not public CA trust.
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| e.to_string())?;
    verifier
        .verify_server_cert(
            leaf,
            &chain[1..],
            &ServerName::try_from(host).map_err(|e| e.to_string())?,
            &[],
            UnixTime::now(),
        )
        .map_err(|e| {
            format!(
                "TLS-сертификат не подходит для {host}, просрочен или имеет неверную цепочку: {e}"
            )
        })?;
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|e| format!("Не удалось создать {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn check_service_environment() -> Result<(), String> {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    if !uid.status.success() || uid.stdout != b"0\n" {
        return Err("Для установки системной службы запустите мастер через sudo. Для запуска в терминале root не нужен.".into());
    }
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("На этой машине не запущен systemd. Выберите запуск в терминале или сохранение конфигурации.".into());
    }
    for path in [UNIT_PATH, BINARY_PATH, SERVICE_STATE_ROOT] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{path} уже существует. Существующая установка не изменена."
            ));
        }
    }
    Ok(())
}
fn systemd_quote(path: &Path) -> String {
    let value = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{value}\"")
}
fn service_unit(directory: &Path) -> String {
    format!(
        "[Unit]\nDescription=Portal network coordinator\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=exec\nDynamicUser=yes\nStateDirectory=portal-coordinator\nStateDirectoryMode=0700\nLoadCredential={}\nLoadCredential={}\nLoadCredential={}\nExecStart={BINARY_PATH} --config %d/config.json\nRestart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(&PathBuf::from(format!(
            "config.json:{}",
            directory.join("service.json").display()
        ))),
        systemd_quote(&PathBuf::from(format!(
            "cert.pem:{}",
            directory.join("cert.pem").display()
        ))),
        systemd_quote(&PathBuf::from(format!(
            "key.pem:{}",
            directory.join("key.pem").display()
        )))
    )
}
fn install_service(plan: &Plan) -> Result<(), String> {
    check_service_environment()?;
    let mut config = plan.config.clone();
    config.tls.cert_file = Path::new(SERVICE_CREDENTIALS).join("cert.pem");
    config.tls.key_file = Path::new(SERVICE_CREDENTIALS).join("key.pem");
    write_new(
        &plan.directory.join("service.json"),
        &serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
        0o600,
    )?;
    fs::create_dir_all(Path::new(BINARY_PATH).parent().unwrap()).map_err(|e| e.to_string())?;
    let binary =
        fs::read(std::env::current_exe().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    write_new(Path::new(BINARY_PATH), &binary, 0o755)?;
    write_new(
        Path::new(UNIT_PATH),
        service_unit(&plan.directory).as_bytes(),
        0o644,
    )?;
    for args in [
        vec!["daemon-reload"],
        vec!["enable", "--now", UNIT],
        vec!["is-active", "--quiet", UNIT],
    ] {
        let status = Command::new("systemctl")
            .args(&args)
            .status()
            .map_err(|e| format!("Не удалось вызвать systemctl: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemctl {} завершился ошибкой. Файлы сохранены; проверьте journalctl -u {UNIT}. Повторное создание сети не требуется.",
                args.join(" ")
            ));
        }
    }
    wait_ready(plan)?;
    Ok(())
}

fn show_admin<R: BufRead, W: Write>(prompt: &mut Prompt<R, W>, state: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut token = Zeroizing::new(String::new());
    fs::File::open(state.join("admin.token"))
        .and_then(|file| file.take(128).read_to_string(&mut token))
        .map_err(|e| {
            format!("Не удалось прочитать токен; проверьте состояние координатора: {e}")
        })?;
    let value = token.trim();
    if value.len() != 68
        || !value.starts_with("usr_")
        || !value.as_bytes()[4..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err("Неверный формат сохранённого токена admin".into());
    }
    prompt.say(value)
}

fn trusted_chain(cert: &[u8]) -> Result<rustls::RootCertStore, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let chain: Vec<_> = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            chain
                .last()
                .ok_or("PEM-файл не содержит сертификат")?
                .clone(),
        )
        .map_err(|e| e.to_string())?;
    Ok(roots)
}
fn health(plan: &Plan) -> Result<(), String> {
    use std::{io::Read, net::TcpStream, time::Duration};
    let mut address = plan.config.listen;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        });
    }
    let socket = TcpStream::connect_timeout(&address, Duration::from_millis(500))
        .map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(trusted_chain(&plan.cert)?)
        .with_no_client_auth();
    let name =
        rustls::pki_types::ServerName::try_from(plan.host.clone()).map_err(|e| e.to_string())?;
    let connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    write!(
        stream,
        "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        plan.host
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::BufReader::new(stream.take(4096))
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if !line.starts_with("HTTP/1.1 200 ") {
        return Err("Проверка /health не вернула HTTP 200".into());
    }
    Ok(())
}
fn wait_ready(plan: &Plan) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match health(plan) {
            Ok(()) => return Ok(()),
            Err(error) if std::time::Instant::now() >= deadline => {
                return Err(format!(
                    "Служба установлена, но HTTPS-проверка готовности не прошла: {error}. Проверьте journalctl -u {UNIT}; конфигурация сохранена."
                ));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answers(directory: &Path, text: &str) -> Result<Option<Plan>, String> {
        let mut prompt = Prompt {
            input: Cursor::new(text.as_bytes()),
            output: Vec::new(),
        };
        collect(&mut prompt, Some(directory.to_owned()))
    }
    fn plan(directory: &Path) -> Plan {
        answers(directory, "3\nlocalhost\n\n2\nнет\nда\n")
            .unwrap()
            .unwrap()
    }
    #[test]
    fn host_validation_handles_ipv6_idn_and_rejects_urls_and_unreachable_addresses() {
        for (input, expected) in [
            ("localhost", "localhost"),
            ("vpn.example.com", "vpn.example.com"),
            ("127.0.0.1", "127.0.0.1"),
            ("[::1]", "::1"),
            ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
        ] {
            assert_eq!(parse_host(input).unwrap(), expected);
        }
        for input in [
            "https://example.com",
            "example.com:8443",
            "example.com/a",
            "u:p@example.com",
            "example.com?q=1",
            "example.com#x",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "0x0",
            "bad\nname",
            "a..b",
            "-a.test",
            "*.example.com",
        ] {
            assert!(parse_host(input).is_err(), "{input}");
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn wizard_saves_private_valid_configuration_and_never_overwrites_it() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("installation with spaces");
        let plan = plan(&directory);
        assert!(
            !directory.exists(),
            "collect/preview must not mutate filesystem"
        );
        let config_path = save(&plan).await.unwrap();
        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(config.state_dir, directory.join("state"));
        assert!(config.stun.enabled);
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["config.json", "cert.pem", "key.pem"] {
            assert_eq!(
                fs::metadata(directory.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(
            !config.state_dir.exists(),
            "save-only must not create a network or admin token"
        );
        let original = fs::read(directory.join("key.pem")).unwrap();
        assert!(save(&plan).await.is_err());
        assert!(answers(&directory, "3\n").is_err());
        assert_eq!(fs::read(directory.join("key.pem")).unwrap(), original);
    }
    #[tokio::test]
    async fn cancellation_eof_invalid_inputs_and_tls_errors_do_not_create_installation() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("cancelled");
        assert!(
            answers(&directory, "3\nlocalhost\n\n2\nнет\nнет\n")
                .unwrap()
                .is_none()
        );
        assert!(answers(&directory, "3\nlocalhost\n").is_err());
        assert!(!directory.exists());
        // Invalid values are retried rather than accepted or written to disk.
        let plan = answers(
            &directory,
            "wrong\n3\nhttp://bad/path\nlocalhost\n127.0.0.1:0\n127.0.0.1:9443\n2\nнет\nда\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.origin(), "https://localhost:9443");
        assert!(!directory.exists());
        let wrong_key = Zeroizing::new(
            rcgen::KeyPair::generate()
                .unwrap()
                .serialize_pem()
                .into_bytes(),
        );
        assert!(
            validate_tls("localhost", &plan.cert, &wrong_key)
                .await
                .is_err()
        );
        assert!(
            validate_tls("different.example", &plan.cert, &plan.key)
                .await
                .is_err()
        );
        let mut plan = plan;
        plan.key = wrong_key;
        assert!(save(&plan).await.is_err());
        assert!(
            !directory.exists(),
            "TLS validation must precede all writes"
        );
    }
    #[tokio::test]
    async fn imported_certificate_is_checked_for_expiry() {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        assert!(
            validate_tls(
                "localhost",
                cert.pem().as_bytes(),
                key.serialize_pem().as_bytes()
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn ipv6_and_custom_address_pools_survive_serialization() {
        let temp = tempfile::tempdir().unwrap();
        let plan = answers(
            &temp.path().join("ipv6"),
            "3\n[::1]\n\n2\nда\n10.78.0.1/24\n10.78.0.0/24\nfd78::/64\nда\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.config.listen, "[::1]:8443".parse().unwrap());
        assert_eq!(plan.origin(), "https://[::1]:8443");
        assert_eq!(plan.config.ipv4_network.to_string(), "10.78.0.0/24");
        let restored: Config =
            serde_json::from_slice(&serde_json::to_vec(&plan.config).unwrap()).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.ipv6_network.to_string(), "fd78::/64");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generated_configuration_starts_real_https_and_health_rejects_wrong_hostname() {
        let temp = tempfile::tempdir().unwrap();
        let mut plan = plan(&temp.path().join("server"));
        plan.config.listen.set_port(0);
        save(&plan).await.unwrap();
        // Emulate systemd DynamicUser's StateDirectory symlink: the database
        // itself must live in a real child directory, not in the symlink.
        #[cfg(unix)]
        {
            let state_root = temp.path().join("private-state");
            fs::create_dir(&state_root).unwrap();
            let state_link = temp.path().join("state-link");
            std::os::unix::fs::symlink(&state_root, &state_link).unwrap();
            plan.config.state_dir = state_link.join("data");
        }
        let coordinator = portal_coordinator::Coordinator::open(plan.config.clone())
            .await
            .unwrap();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move { coordinator.serve(server_handle).await });
        plan.config.listen = handle.listening().await.unwrap();
        health(&plan).unwrap();
        assert!(plan.config.state_dir.join("admin.token").is_file());
        let token = fs::read(plan.config.state_dir.join("admin.token")).unwrap();
        plan.host = "wrong.example".into();
        assert!(health(&plan).is_err());
        assert_eq!(
            fs::read(plan.config.state_dir.join("admin.token")).unwrap(),
            token
        );
        handle.shutdown();
        server.await.unwrap().unwrap();
    }
    #[test]
    fn service_credentials_and_paths_are_escaped_and_unit_passes_systemd_validation() {
        let temp = tempfile::tempdir().unwrap();
        let unit = service_unit(Path::new("/etc/portal % instance"));
        assert!(unit.contains("DynamicUser=yes\n"));
        assert!(unit.contains("StateDirectoryMode=0700\n"));
        assert!(unit.contains("LoadCredential=\"key.pem:/etc/portal %% instance/key.pem\""));
        assert!(unit.contains("--config %d/config.json"));
        assert!(!unit.contains("usr_"));
        assert_eq!(systemd_quote(Path::new("/a\"b\\c%")), "\"/a\\\"b\\\\c%%\"");
        // Verify generated syntax without installing or starting a host service.
        if Command::new("systemd-analyze")
            .arg("--version")
            .output()
            .is_ok()
        {
            let path = temp.path().join(UNIT);
            fs::write(&path, unit.replace(BINARY_PATH, "/usr/bin/true")).unwrap();
            let result = Command::new("systemd-analyze")
                .args(["verify", "--man=no"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
