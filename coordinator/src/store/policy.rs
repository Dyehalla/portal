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
        permissions.retain(|_, allowed| !allowed.tcp.is_empty());
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
