//! Single-network account session, persisted by the agent, never browser storage.
use crate::{
    ManagedConfig,
    managed::{Agent, Prepared},
    private_file,
    runtime::Runtime,
};
use portal_net::{
    client::{ClientError, CoordinatorClient},
    model::*,
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
pub(crate) struct Profile {
    config: ManagedConfig,
    token: String,
    registration_name: Option<String>,
    user: Option<User>,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(default)]
    pending_device_token: Option<String>,
}
impl Drop for Profile {
    fn drop(&mut self) {
        self.token.zeroize();
        if let Some(token) = &mut self.pending_device_token {
            token.zeroize();
        }
    }
}

pub(crate) struct Account {
    path: Option<PathBuf>,
    profile: Option<Profile>,
    pub agent: Option<Arc<Agent>>,
    pub expected_owner: Option<String>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Account {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Login {
    pub address: String,
    pub token: Option<String>,
    pub user_name: Option<String>,
    pub ca_pem: Option<String>,
}
impl Drop for Login {
    fn drop(&mut self) {
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
}
#[derive(Serialize)]
pub(crate) struct View {
    pub configured: bool,
    pub address: Option<String>,
    pub user: Option<User>,
    pub devices: Vec<Device>,
    pub needs_device: bool,
    pub device_name: String,
    pub pending_user_name: Option<String>,
    pub error: Option<String>,
    pub activation_error: Option<String>,
}

pub(crate) fn normalize_address(value: &str) -> Result<String, String> {
    let value = value.trim();
    let address = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    portal_net::client::coordinator_origin(&address)
}
fn failure(error: ClientError) -> String {
    match error {
        ClientError::Unauthorized => "Токен пользователя неверен или отозван. Нужен токен входа usr_, а не токен устройства или локального API.".into(),
        ClientError::Http(409) => "Имя аккаунта или ключ устройства уже используется. Проверьте существующую регистрацию.".into(),
        ClientError::Http(403) => "Координатор отказал в регистрации или доступе.".into(),
        ClientError::Tls => "Сертификат координатора не принят. Проверьте имя сервера и срок сертификата. Для собственного центра сертификации выберите доверенный PEM-файл.".into(),
        ClientError::Timeout => "Координатор не ответил вовремя. Повторите запрос: этап регистрации и секреты сохранены.".into(),
        ClientError::Transport => "Нет HTTPS-соединения с координатором. Проверьте адрес, доступность сервера и сертификат. Для собственного CA выберите PEM-файл в настройках доверия.".into(),
        _ => "Координатор не выполнил запрос. Попробуйте ещё раз.".into(),
    }
}
impl Account {
    pub fn open(path: Option<PathBuf>) -> Result<Self, String> {
        let profile = match path.as_ref() {
            Some(path) if path.try_exists().map_err(|e| e.to_string())? => Some(
                serde_json::from_slice(&private_file::read(path, 65536)?)
                    .map_err(|_| "invalid account profile")?,
            ),
            _ => None,
        };
        Ok(Self {
            path,
            profile,
            agent: None,
            expected_owner: None,
            task: None,
        })
    }
    fn save(&self) -> Result<(), String> {
        let path = self
            .path
            .as_ref()
            .ok_or("Подключение сети доступно при стандартном запуске Portal.")?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(self.profile.as_ref().ok_or("Нет профиля")?)
                .map_err(|_| "Не удалось сохранить профиль")?,
        );
        private_file::write(path, &bytes, false)
    }
    pub(crate) fn client(&self) -> Result<CoordinatorClient, String> {
        let p = self.profile.as_ref().ok_or("Сначала войдите в сеть")?;
        CoordinatorClient::new(&p.config.url, p.token.clone(), p.config.ca_file.as_deref())
    }
    pub async fn login(&mut self, request: Login, key: &str) -> Result<View, String> {
        let address = normalize_address(&request.address)?;
        let path = self
            .path
            .as_ref()
            .ok_or("Подключение сети доступно при стандартном запуске Portal.")?;
        if let Some(p) = &self.profile {
            if p.config.url != address {
                return Err("Этот клиент уже настроен для другой сети. Несколько сетей пока не поддерживаются.".into());
            }
            if request.user_name.is_some()
                && p.registration_name != request.user_name
                && p.user.is_some()
            {
                return Err(
                    "Регистрация уже начата. Продолжите её с прежним именем аккаунта.".into(),
                );
            }
        }
        let registering = request.user_name.is_some();
        if registering && self.agent.is_some() && self.profile.is_none() {
            return Err("Агент уже зарегистрирован. Войдите с токеном его владельца.".into());
        }
        let secret = if let Some(p) = &self.profile {
            if registering {
                p.token.clone()
            } else {
                request.token.clone().ok_or("Введите токен пользователя")?
            }
        } else if registering {
            use rand::RngCore;
            let mut bytes = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(bytes.as_mut());
            format!(
                "usr_{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        } else {
            request.token.clone().ok_or("Введите токен пользователя")?
        };
        if !secret.starts_with("usr_")
            || secret.len() != 68
            || !secret.as_bytes()[4..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(
                "Нужен токен пользователя usr_ из 64 шестнадцатеричных символов после префикса."
                    .into(),
            );
        }
        let ca_file = if let Some(pem) = &request.ca_pem {
            let ca = path.with_extension(format!("ca-{:016x}.pem", rand::random::<u64>()));
            private_file::write(&ca, pem.as_bytes(), false)?;
            Some(ca)
        } else {
            self.profile.as_ref().and_then(|p| p.config.ca_file.clone())
        };
        let client = CoordinatorClient::new(&address, secret.clone(), ca_file.as_deref())?;
        if !registering {
            let user = client.me().await.map_err(failure)?;
            if self
                .expected_owner
                .as_ref()
                .is_some_and(|id| id != &user.id)
            {
                return Err("Нужен токен владельца текущего устройства.".into());
            }
            if self
                .profile
                .as_ref()
                .and_then(|p| p.user.as_ref())
                .is_some_and(|old| old.id != user.id)
            {
                return Err(
                    "Профиль принадлежит другому аккаунту. Текущие credentials сохранены.".into(),
                );
            }
            if let Some(p) = &mut self.profile {
                p.token = secret;
                p.user = Some(user);
                p.config.ca_file = ca_file;
            } else {
                self.profile = Some(Profile {
                    config: self.agent.as_ref().map(|a| a.config.clone()).unwrap_or(
                        ManagedConfig {
                            url: address,
                            credential_file: path.with_extension("device.json"),
                            policy_file: path.with_extension("policy.json"),
                            map_file: path.with_extension("map.json"),
                            ca_file: ca_file.clone(),
                            device_name: format!("device-{:08x}", rand::random::<u32>()),
                            ..Default::default()
                        },
                    ),
                    token: secret,
                    registration_name: None,
                    user: Some(user),
                    network_id: None,
                    pending_device_token: None,
                });
            }
            self.save()?;
        } else {
            if self.profile.is_none() {
                self.profile = Some(Profile {
                    config: self.agent.as_ref().map(|a| a.config.clone()).unwrap_or(
                        ManagedConfig {
                            url: address,
                            credential_file: path.with_extension("device.json"),
                            policy_file: path.with_extension("policy.json"),
                            map_file: path.with_extension("map.json"),
                            ca_file: ca_file.clone(),
                            device_name: format!("device-{:08x}", rand::random::<u32>()),
                            ..Default::default()
                        },
                    ),
                    token: secret,
                    registration_name: request.user_name.clone(),
                    user: None,
                    network_id: None,
                    pending_device_token: None,
                });
                self.save()?; // Before sending: a timeout can safely resume the same registration.
            }
            if self.profile.as_ref().unwrap().user.is_none() {
                self.profile.as_mut().unwrap().registration_name = request.user_name.clone();
                self.save()?;
                let reply = client
                    .register_user(request.user_name.as_deref().unwrap())
                    .await
                    .map_err(failure)?;
                self.profile.as_mut().unwrap().user = Some(reply.user);
                self.profile.as_mut().unwrap().config.ca_file = ca_file;
                self.save()?;
            }
        }
        self.view(key).await
    }
    pub async fn view(&self, key: &str) -> Result<View, String> {
        let Some(p) = &self.profile else {
            return Ok(View {
                configured: false,
                address: None,
                user: None,
                devices: vec![],
                needs_device: false,
                device_name: String::new(),
                pending_user_name: None,
                error: None,
                activation_error: None,
            });
        };
        let (devices, error) = if p.user.is_some() {
            match self.client()?.devices().await {
                Ok(devices) => (devices, None),
                Err(error) => (vec![], Some(failure(error))),
            }
        } else {
            (vec![], None)
        };
        Ok(View {
            configured: true,
            address: Some(p.config.url.clone()),
            user: p.user.clone(),
            needs_device: error.is_none()
                && (p.pending_device_token.is_some()
                    || !devices.iter().any(|d| d.public_key == key)),
            devices,
            device_name: p.config.device_name.clone(),
            error,
            activation_error: None,
            pending_user_name: p
                .user
                .is_none()
                .then(|| p.registration_name.clone())
                .flatten(),
        })
    }
    pub fn export(&self) -> Result<String, String> {
        Ok(self
            .profile
            .as_ref()
            .filter(|p| p.user.is_some())
            .ok_or("Нет сохранённого токена пользователя")?
            .token
            .clone())
    }
    pub async fn enroll(&mut self, name: String, key: &str) -> Result<(), String> {
        let devices = self.client()?.devices().await.map_err(failure)?;
        let p = self.profile.as_mut().ok_or("Сначала войдите в сеть")?;
        if !p
            .config
            .credential_file
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            if p.pending_device_token.is_none() && devices.iter().any(|d| d.public_key == key) {
                return Err("Устройство уже зарегистрировано, но локальные credentials утрачены. Восстановите локальную копию; автоматическая ротация отключена, чтобы не отозвать живой агент.".into());
            }
            if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err("Введите имя устройства до 128 символов".into());
            }
            p.config.device_name = name;
            if p.pending_device_token.is_none() {
                use rand::RngCore;
                let mut bytes = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(bytes.as_mut());
                p.pending_device_token = Some(format!(
                    "dev_{}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
            }
            let bytes =
                Zeroizing::new(serde_json::to_vec(p).map_err(|_| "Ошибка сохранения профиля")?);
            private_file::write(self.path.as_ref().ok_or("Нет профиля")?, &bytes, false)?;
            let client = CoordinatorClient::new(
                &p.config.url,
                p.token.clone(),
                p.config.ca_file.as_deref(),
            )?;
            let reply = client
                .enroll_device(
                    &RegisterDevice {
                        name: p.config.device_name.clone(),
                        public_key: key.to_owned(),
                        endpoints: vec![],
                    },
                    p.pending_device_token.as_deref().unwrap(),
                )
                .await
                .map_err(failure)?;
            if reply.device.public_key != key
                || Some(reply.access_token.as_str()) != p.pending_device_token.as_deref()
            {
                return Err("Координатор вернул другое устройство".into());
            }
            let bytes = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"coordinator": p.config.url, "device": reply.device, "access_token": reply.access_token})).map_err(|_| "Ошибка сохранения credentials")?);
            private_file::write(&p.config.credential_file, &bytes, true)?;
            if let Some(mut token) = p.pending_device_token.take() {
                token.zeroize();
            }
        }
        if !p
            .config
            .policy_file
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            private_file::write(&p.config.policy_file, b"{}", true)?;
        }
        self.save()?;
        Ok(())
    }
    pub async fn activate(
        &mut self,
        name: String,
        runtime: &Arc<Mutex<Runtime>>,
    ) -> Result<(), String> {
        if self.agent.is_some() {
            return Ok(());
        }
        let key = runtime
            .lock()
            .map_err(|_| "Агент недоступен")?
            .snapshot()?
            .interface
            .public_key;
        self.enroll(name, &key).await?;
        let p = self.profile.as_ref().unwrap();
        let prepared =
            Prepared::load(p.config.clone(), portal_net::policy::public_key(&key)?).await?;
        if p.network_id
            .as_ref()
            .is_some_and(|id| id != &prepared.map.network_id)
        {
            return Err(
                "По этому адресу изменилась сеть. Автоматическое подключение остановлено.".into(),
            );
        }
        self.profile.as_mut().unwrap().network_id = Some(prepared.map.network_id.clone());
        self.save()?;
        let access = runtime
            .lock()
            .map_err(|_| "Агент недоступен")?
            .prepare_web_network(&prepared.map)?;
        let agent = Agent::attach(prepared, runtime.clone(), access)?;
        self.agent = Some(agent.clone());
        let failed_runtime = runtime.clone();
        self.task = Some(tokio::spawn(async move {
            let _ = agent.run().await;
            if let Ok(mut runtime) = failed_runtime.lock() {
                if let Some(state) = &mut runtime.managed {
                    state.connected = false;
                    state.deadline = std::time::Instant::now();
                }
            }
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses_use_https_standard_port_and_reject_non_origins() {
        assert_eq!(
            normalize_address("example.com").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_address("example.com:9443").unwrap(),
            "https://example.com:9443"
        );
        for value in [
            "http://example.com",
            "https://u:p@example.com",
            "example.com/a",
            "example.com?q=1",
            "example.com#secret",
        ] {
            assert!(normalize_address(value).is_err());
        }
    }
    #[tokio::test]
    async fn account_registration_trust_restart_and_enrollment_resume_without_tun() {
        use portal_coordinator::{Coordinator, config::Config};
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap();
        let ca = dir.path().join("server.pem");
        let tls_key = dir.path().join("server.key");
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        std::fs::write(&tls_key, cert.key_pair.serialize_pem()).unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"listen":"127.0.0.1:0","state_dir":dir.path().join("server"),"tls":{"cert_file":ca,"key_file":tls_key}})).unwrap();
        let server = Coordinator::open(config).await.unwrap();
        let handle = axum_server::Handle::new();
        let task = tokio::spawn(server.serve(handle.clone()));
        let address = format!("https://{}", handle.listening().await.unwrap());
        let path = dir.path().join("account.json");
        let key = portal_net::policy::key_hex(
            &boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from([31; 32]))
                .to_bytes(),
        );
        let mut account = Account::open(Some(path.clone())).unwrap();
        assert!(
            account
                .login(
                    Login {
                        address: address.clone(),
                        token: None,
                        user_name: Some("Анна".into()),
                        ca_pem: None
                    },
                    &key
                )
                .await
                .is_err()
        );
        // The generated secret was saved before the untrusted HTTPS request failed.
        let pending = account.profile.as_ref().unwrap().token.clone();
        drop(account);
        let mut account = Account::open(Some(path.clone())).unwrap();
        let view = account
            .login(
                Login {
                    address: address.clone(),
                    token: None,
                    user_name: Some("Анна".into()),
                    ca_pem: Some(cert.cert.pem()),
                },
                &key,
            )
            .await
            .unwrap();
        assert_eq!(view.user.unwrap().name, "Анна");
        assert!(view.needs_device);
        assert_eq!(account.export().unwrap(), pending);
        account
            .enroll("device-service-name".into(), &key)
            .await
            .unwrap();
        let p = account.profile.as_ref().unwrap();
        let credentials = private_file::read(&p.config.credential_file, 65536).unwrap();
        // Simulate a lost enrollment response: retain the pending secret and retry.
        let credential: serde_json::Value = serde_json::from_slice(&credentials).unwrap();
        let credential_path = p.config.credential_file.clone();
        account.profile.as_mut().unwrap().pending_device_token =
            Some(credential["access_token"].as_str().unwrap().into());
        account.save().unwrap();
        std::fs::remove_file(&credential_path).unwrap();
        drop(account);
        let mut account = Account::open(Some(path.clone())).unwrap();
        account
            .enroll("device-service-name".into(), &key)
            .await
            .unwrap();
        let view = account.view(&key).await.unwrap();
        assert_eq!(view.devices.len(), 1);
        assert!(!view.needs_device);
        assert_eq!(
            private_file::read(&credential_path, 65536)
                .unwrap()
                .as_slice(),
            credentials.as_slice()
        );
        let wrong = account
            .login(
                Login {
                    address: "different.example".into(),
                    token: Some(pending.clone()),
                    user_name: None,
                    ca_pem: None,
                },
                &key,
            )
            .await;
        assert!(wrong.is_err());
        assert_eq!(account.export().unwrap(), pending);
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        handle.shutdown();
        task.await.unwrap().unwrap();
    }
}
