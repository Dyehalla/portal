use super::*;
use std::{fs, io::Write, path::Path};

pub(super) fn initialize(
    db: &mut Connection,
    config: &Config,
    admin: Credential,
) -> std::result::Result<(), String> {
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if !matches!(version, 0 | 2 | 3 | 4) {
        return Err(
            "unsupported coordinator database schema; explicit migration is required".into(),
        );
    }
    db.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;
    db.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| e.to_string())?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    tx.execute_batch("
            CREATE TABLE IF NOT EXISTS network(
                id INTEGER PRIMARY KEY CHECK(id=1), network_id TEXT NOT NULL, generation TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision>=0), next_slot INTEGER NOT NULL,
                ipv4 TEXT NOT NULL, ipv6 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
                token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL CHECK(created_at>=0));
            CREATE TABLE IF NOT EXISTS devices(
                id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
                public_key TEXT NOT NULL UNIQUE, token_hash BLOB NOT NULL UNIQUE,
                ipv4 TEXT NOT NULL UNIQUE, ipv6 TEXT NOT NULL UNIQUE, endpoints TEXT NOT NULL,
                created_at INTEGER NOT NULL CHECK(created_at>=0), revoked INTEGER NOT NULL DEFAULT 0,
                policy_revision INTEGER NOT NULL DEFAULT 0 CHECK(policy_revision>=0),
                permissions TEXT NOT NULL DEFAULT '{}');
            CREATE INDEX IF NOT EXISTS device_owner ON devices(owner_user_id);
        ").map_err(|e| e.to_string())?;
    if matches!(version, 2 | 3) {
        let revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE revoked<>0)",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if revoked {
            return Err("cannot remove users.revoked with disabled accounts; explicit migration is required".into());
        }
        tx.execute_batch("ALTER TABLE users DROP COLUMN revoked;")
            .map_err(|e| e.to_string())?;
    }
    if version == 2 {
        // User-wide grants cannot be carried over as implicit device grants.
        // Keep the previous confirmed policies for manual inspection, but close access.
        tx.execute_batch(
            "ALTER TABLE devices RENAME COLUMN policy TO legacy_user_policy;
                ALTER TABLE devices ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}';
                UPDATE devices SET policy_revision=policy_revision+1;",
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE network SET generation=?,revision=revision+1 WHERE id=1",
            [credentials::random_hex(16)],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.pragma_update(None, "user_version", 4)
        .map_err(|e| e.to_string())?;
    let exists: bool = tx
        .query_row("SELECT EXISTS(SELECT 1 FROM network)", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if !exists {
        tx.execute(
            "INSERT INTO network VALUES(1,?,?,0,1,?,?)",
            params![
                credentials::random_hex(16),
                credentials::random_hex(16),
                config.ipv4_network.to_string(),
                config.ipv6_network.to_string(),
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO users(id,name,is_admin,token_hash,created_at) VALUES(?,'admin',1,?,?)",
            params![
                format!("u_{}", credentials::random_hex(16)),
                admin.hash.as_slice(),
                now()
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    let pools: (String, String) = tx
        .query_row("SELECT ipv4,ipv6 FROM network WHERE id=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|e| e.to_string())?;
    if pools
        != (
            config.ipv4_network.to_string(),
            config.ipv6_network.to_string(),
        )
    {
        return Err(
            "address pools differ from persisted state; explicit migration is required".into(),
        );
    }
    let admin_user = authenticated_user(&tx, admin)
        .map_err(|_| "admin.token does not match the administrator account".to_owned())?;
    if !admin_user.is_admin {
        return Err("admin.token does not belong to the administrator".into());
    }
    let has_archive: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name='legacy_user_policy')",
            [], |r| r.get(0),
        ).map_err(|e| e.to_string())?;
    if has_archive {
        archive_legacy_policies(&tx, &config.state_dir)?;
        tx.execute_batch("ALTER TABLE devices DROP COLUMN legacy_user_policy;")
            .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

// Write the archive durably before removing its database column. A crash before COMMIT
// leaves the old rows intact; retries accept only an identical existing archive.
fn archive_legacy_policies(db: &Connection, directory: &Path) -> std::result::Result<(), String> {
    let mut query = db
        .prepare("SELECT id,legacy_user_policy FROM devices ORDER BY id")
        .map_err(|e| e.to_string())?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()
        .map_err(|e| e.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(&rows).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_archive(directory, &bytes)
        .map_err(|e| format!("could not archive legacy user policies: {e}"))
}

fn write_archive(directory: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let path = directory.join("legacy-user-policies.json");
    if path.try_exists()? {
        credentials::check_private(&path, false)?;
        if fs::read(&path)? != bytes {
            return Err(std::io::Error::other(
                "existing archive differs; refusing to overwrite it",
            ));
        }
        // Covers retrying after a crash between linking the archive and syncing the directory.
        fs::File::open(&path)?.sync_all()?;
    } else {
        let temporary = directory.join(format!(
            ".legacy-policies-{}.tmp",
            credentials::random_hex(16)
        ));
        let result = (|| {
            let mut file = credentials::create_private(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::hard_link(&temporary, &path)
        })();
        let _ = fs::remove_file(&temporary);
        result?;
    }
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
