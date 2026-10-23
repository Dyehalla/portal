use crate::{
    config::Config,
    credentials::{self, Credential, Role},
    error::{Error, Result},
    models::*,
};
use ipnet::{Ipv4Net, Ipv6Net};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::{
    fs::File,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod connections;
mod devices;
mod network_map;
mod policy;
mod schema;
mod users;
mod validate;

pub(crate) use connections::ConnectionContext;
use devices::{authenticated_device, device};
use policy::policy;
use users::{authenticated_user, user};
use validate::{endpoints, name, public_key};

const USER_COLUMNS: &str = "id,name,is_admin,created_at";
const DEVICE_COLUMNS: &str = "id,owner_user_id,name,public_key,ipv4,ipv6,endpoints,created_at";

pub(crate) struct Store {
    connection: Connection,
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
    _directory_lock: File,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64 - 3600) as i64
}

fn counter(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value.try_into().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}

fn bump(db: &Connection) -> Result<()> {
    db.execute("UPDATE network SET revision=revision+1 WHERE id=1", [])?;
    Ok(())
}

impl Store {
    pub fn open(config: &Config) -> std::result::Result<Self, String> {
        credentials::prepare_directory(&config.state_dir).map_err(|e| e.to_string())?;
        let directory_lock =
            credentials::lock_directory(&config.state_dir).map_err(|e| e.to_string())?;
        let path = config.state_dir.join("network.sqlite3");
        let admin =
            credentials::admin_key(&config.state_dir, path.exists()).map_err(|e| e.to_string())?;
        match credentials::create_private(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        credentials::check_private(&path, false).map_err(|e| e.to_string())?;
        let mut db = Connection::open(path).map_err(|e| e.to_string())?;
        db.busy_timeout(Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        db.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| e.to_string())?;
        schema::initialize(&mut db, config, admin)?;
        Ok(Self {
            connection: db,
            ipv4: config.ipv4_network,
            ipv6: config.ipv6_network,
            _directory_lock: directory_lock,
        })
    }

    pub fn revision(&self) -> Result<u64> {
        Ok(self
            .connection
            .query_row("SELECT revision FROM network WHERE id=1", [], |r| {
                counter(r, 0)
            })?)
    }
}
