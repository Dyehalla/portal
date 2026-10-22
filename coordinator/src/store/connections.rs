use super::*;

pub(crate) struct ConnectionContext {
    pub requester: Device,
    pub target: Device,
    permissions: PeerPermissions,
    target_policy_revision: u64,
    network_id: String,
    generation: String,
    revision: u64,
    pub generated_at: u64,
}

impl ConnectionContext {
    fn information(&self, request_id: &str, expires_at: u64, peer: Device) -> ConnectionInfo {
        ConnectionInfo {
            request_id: request_id.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            network_id: self.network_id.clone(),
            generation: self.generation.clone(),
            revision: self.revision,
            peer,
            permissions: self.permissions.clone(),
            target_policy_revision: self.target_policy_revision,
            expires_at,
        }
    }

    pub fn for_requester(&self, request_id: &str, expires_at: u64) -> ConnectionInfo {
        self.information(request_id, expires_at, self.target.clone())
    }

    pub fn for_target(&self, request_id: &str, expires_at: u64) -> ConnectionInfo {
        self.information(request_id, expires_at, self.requester.clone())
    }
}

fn connection_context(
    db: &Connection,
    credential: Credential,
    target_id: &str,
) -> Result<ConnectionContext> {
    let requester = authenticated_device(db, credential)?;
    if target_id.len() > 128 || target_id.is_empty() {
        return Err(Error::bad_request(
            "peer_device_id must contain 1-128 bytes",
        ));
    }
    if requester.id == target_id {
        return Err(Error::bad_request("a device cannot connect to itself"));
    }
    let target = db
        .query_row(
            &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id=? AND revoked=0"),
            [target_id],
            device,
        )
        .optional()?
        .ok_or_else(Error::not_found)?;
    let target_policy = policy(db, &target.id)?;
    let permissions = target_policy
        .permissions
        .get(&requester.public_key)
        .filter(|p| !p.tcp.is_empty())
        .cloned()
        .ok_or_else(|| {
            Error::forbidden("destination does not permit connections from this peer")
        })?;
    if requester.endpoints.is_empty() || target.endpoints.is_empty() {
        return Err(Error::conflict(
            "both peers must publish endpoint candidates before requesting a connection",
        ));
    }
    let (network_id, generation, revision) = db.query_row(
        "SELECT network_id,generation,revision FROM network WHERE id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, counter(row, 2)?)),
    )?;
    Ok(ConnectionContext {
        requester,
        target,
        permissions,
        target_policy_revision: target_policy.revision,
        network_id,
        generation,
        revision,
        generated_at: now() as u64,
    })
}

impl Store {
    pub fn prepare_connection(
        &mut self,
        credential: Credential,
        target_id: &str,
    ) -> Result<ConnectionContext> {
        let tx = self.connection.transaction()?;
        let context = connection_context(&tx, credential, target_id)?;
        tx.commit()?;
        Ok(context)
    }

    pub fn answer_connection(
        &mut self,
        target_credential: Credential,
        source_credential: Credential,
        target_id: &str,
    ) -> Result<ConnectionContext> {
        let tx = self.connection.transaction()?;
        let target = authenticated_device(&tx, target_credential)?;
        if target.id != target_id {
            return Err(Error::not_found());
        }
        let context = connection_context(&tx, source_credential, target_id)?;
        tx.commit()?;
        Ok(context)
    }
}
