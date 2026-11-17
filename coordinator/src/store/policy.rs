use super::*;

pub(super) fn policy(db: &Connection, id: &str) -> Result<DevicePolicy> {
    let (revision, permissions): (u64, String) = db.query_row(
        "SELECT policy_revision,permissions FROM devices WHERE id=?",
        [id],
        |row| Ok((counter(row, 0)?, row.get(1)?)),
    )?;
    Ok(DevicePolicy {
        revision,
        permissions: serde_json::from_str(&permissions).map_err(|_| Error::internal())?,
    })
}

impl Store {
    pub fn publish_policy(
        &mut self,
        credential: Credential,
        request: PublishPolicy,
    ) -> Result<DevicePolicy> {
        let tx = self.connection.transaction()?;
        let device = authenticated_device(&tx, credential)?;
        if desired(&tx, &device.id)?.is_some() {
            return Err(Error::conflict(
                "policy is managed by the owner; agent acknowledgement required",
            ));
        }
        let current = policy(&tx, &device.id)?;
        if request.base_revision != current.revision {
            return Err(Error::conflict("policy revision mismatch"));
        }
        if request.permissions.len() > 256 {
            return Err(Error::bad_request(
                "at most 256 peer permission entries are allowed",
            ));
        }
        let mut permissions = Permissions::new();
        for (source_key, mut allowed) in request.permissions {
            let source_key = public_key(&source_key)?;
            if source_key == device.public_key {
                return Err(Error::bad_request(
                    "a device cannot grant peer access to itself",
                ));
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE public_key=? AND revoked=0)",
                [&source_key],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(Error::bad_request(
                    "permissions reference an unknown or revoked peer key",
                ));
            }
            allowed.tcp = validate::tcp_ports(allowed.tcp)?;
            if permissions.insert(source_key, allowed).is_some() {
                return Err(Error::bad_request("duplicate peer key after normalization"));
            }
        }
        permissions.retain(|_, allowed| !allowed.tcp.is_empty() || allowed.terminal);
        let mut result = current;
        if result.permissions != permissions {
            tx.execute(
                "UPDATE devices SET policy_revision=policy_revision+1,permissions=? WHERE id=?",
                params![
                    serde_json::to_string(&permissions).map_err(|_| Error::internal())?,
                    device.id
                ],
            )?;
            bump(&tx)?;
            result = policy(&tx, &device.id)?;
        }
        tx.commit()?;
        Ok(result)
    }
}

fn owned_device(db: &Connection, credential: Credential, id: &str) -> Result<Device> {
    let owner = authenticated_user(db, credential)?;
    db.query_row(
        &format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE id=? AND owner_user_id=? AND revoked=0"
        ),
        params![id, owner.id],
        device,
    )
    .optional()?
    .ok_or_else(Error::not_found)
}
pub(super) fn desired(db: &Connection, id: &str) -> Result<Option<DesiredPolicy>> {
    db.query_row(
        "SELECT revision,permissions,applied_revision FROM desired_policies WHERE device_id=?",
        [id],
        |r| {
            let json: String = r.get(1)?;
            Ok((counter(r, 0)?, json, counter(r, 2)?))
        },
    )
    .optional()?
    .map(|(revision, json, applied_revision)| {
        Ok(DesiredPolicy {
            revision,
            permissions: serde_json::from_str(&json).map_err(|_| Error::internal())?,
            applied_revision,
        })
    })
    .transpose()
}
impl Store {
    pub fn desired_policy(&self, credential: Credential) -> Result<Option<DesiredPolicy>> {
        let device = authenticated_device(&self.connection, credential)?;
        desired(&self.connection, &device.id)
    }
    pub fn owner_policy(&self, credential: Credential, id: &str) -> Result<DesiredPolicy> {
        owned_device(&self.connection, credential, id)?;
        if let Some(policy) = desired(&self.connection, id)? {
            return Ok(policy);
        }
        let policy = policy(&self.connection, id)?;
        Ok(DesiredPolicy {
            revision: policy.revision,
            applied_revision: policy.revision,
            permissions: policy.permissions,
        })
    }
    pub fn save_owner_policy(
        &mut self,
        credential: Credential,
        id: &str,
        request: PublishPolicy,
    ) -> Result<DesiredPolicy> {
        let tx = self.connection.transaction()?;
        let target = owned_device(&tx, credential, id)?;
        let result = write_owner_policy(&tx, &target, request)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn acknowledge_policy(
        &mut self,
        credential: Credential,
        revision: u64,
    ) -> Result<DesiredPolicy> {
        let tx = self.connection.transaction()?;
        let target = authenticated_device(&tx, credential)?;
        let mut current = desired(&tx, &target.id)?.ok_or_else(Error::not_found)?;
        if revision != current.revision {
            return Err(Error::conflict("desired policy changed"));
        }
        if current.applied_revision != revision {
            tx.execute(
                "UPDATE devices SET policy_revision=?,permissions=? WHERE id=?",
                params![
                    i64::try_from(revision).map_err(|_| Error::internal())?,
                    serde_json::to_string(&current.permissions).map_err(|_| Error::internal())?,
                    target.id
                ],
            )?;
            tx.execute(
                "UPDATE desired_policies SET applied_revision=? WHERE device_id=?",
                params![
                    i64::try_from(revision).map_err(|_| Error::internal())?,
                    target.id
                ],
            )?;
            bump(&tx)?;
        }
        current.applied_revision = revision;
        tx.commit()?;
        Ok(current)
    }
    pub fn rename_device(
        &mut self,
        credential: Credential,
        id: &str,
        requested: &str,
    ) -> Result<Device> {
        let tx = self.connection.transaction()?;
        let mut target = owned_device(&tx, credential, id)?;
        target.name = name(requested)?;
        tx.execute(
            "UPDATE devices SET name=? WHERE id=?",
            params![target.name, id],
        )?;
        bump(&tx)?;
        tx.commit()?;
        Ok(target)
    }
}

pub(super) fn write_owner_policy(
    tx: &Connection,
    target: &Device,
    request: PublishPolicy,
) -> Result<DesiredPolicy> {
    let id = &target.id;
    let current = match desired(tx, id)? {
        Some(p) => p,
        None => {
            let p = policy(tx, id)?;
            DesiredPolicy {
                revision: p.revision,
                applied_revision: p.revision,
                permissions: p.permissions,
            }
        }
    };
    if request.base_revision != current.revision {
        return Err(Error::conflict("policy revision mismatch"));
    }
    if request.permissions.len() > 256 {
        return Err(Error::bad_request("at most 256 peer entries"));
    }
    let mut permissions = Permissions::new();
    for (key, mut allowed) in request.permissions {
        let key = public_key(&key)?;
        if key == target.public_key {
            return Err(Error::bad_request("cannot grant access to itself"));
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE public_key=? AND revoked=0)",
            [&key],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::bad_request("unknown or revoked source device"));
        }
        allowed.tcp = validate::tcp_ports(allowed.tcp)?;
        if (!allowed.tcp.is_empty() || allowed.terminal)
            && permissions.insert(key, allowed).is_some()
        {
            return Err(Error::bad_request("duplicate source"));
        }
    }
    let revision = current.revision + 1;
    tx.execute("INSERT INTO desired_policies(device_id,revision,permissions,applied_revision) VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET revision=excluded.revision,permissions=excluded.permissions", params![id,i64::try_from(revision).map_err(|_| Error::internal())?,serde_json::to_string(&permissions).map_err(|_| Error::internal())?,i64::try_from(current.applied_revision).map_err(|_| Error::internal())?])?;
    bump(tx)?;
    Ok(DesiredPolicy {
        revision,
        permissions,
        applied_revision: current.applied_revision,
    })
}
