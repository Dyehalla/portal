use super::*;

const PRESENCE_TIMEOUT_SECONDS: u64 = 90;

impl Store {
    pub fn network_map(
        &mut self,
        credential: Credential,
        lease_seconds: u64,
    ) -> Result<NetworkMap> {
        let tx = self.connection.transaction()?;
        let own = authenticated_device(&tx, credential)?;
        let timestamp = now() as u64;
        tx.execute(
            "UPDATE devices SET last_seen=? WHERE id=?",
            params![
                i64::try_from(timestamp).map_err(|_| Error::internal())?,
                &own.id
            ],
        )?;
        let owner = tx.query_row(
            &format!("SELECT {USER_COLUMNS} FROM users WHERE id=?"),
            [&own.owner_user_id],
            user,
        )?;
        let own_policy = policy(&tx, &own.id)?;
        let mut peers = Vec::new();
        {
            let mut query = tx.prepare(&format!(
                "SELECT {DEVICE_COLUMNS} FROM devices WHERE id!=? AND revoked=0 ORDER BY id"
            ))?;
            for candidate in query.query_map([&own.id], device)? {
                let candidate = candidate?;
                let candidate_policy = policy(&tx, &candidate.id)?;
                let incoming = own_policy
                    .permissions
                    .get(&candidate.public_key)
                    .cloned()
                    .unwrap_or_default();
                let outgoing = candidate_policy
                    .permissions
                    .get(&own.public_key)
                    .cloned()
                    .unwrap_or_default();
                let last_seen: u64 = tx.query_row(
                    "SELECT last_seen FROM devices WHERE id=?",
                    [&candidate.id],
                    |row| counter(row, 0),
                )?;
                if !incoming.tcp.is_empty()
                    || incoming.terminal
                    || incoming.files
                    || !outgoing.tcp.is_empty()
                    || outgoing.terminal
                    || outgoing.files
                {
                    peers.push(Peer {
                        device: candidate,
                        online: last_seen > 0
                            && timestamp.saturating_sub(last_seen)
                                <= PRESENCE_TIMEOUT_SECONDS.min(lease_seconds),
                        policy_revision: candidate_policy.revision,
                        incoming,
                        outgoing,
                    });
                }
            }
        }
        let (network_id, generation, revision) = tx.query_row(
            "SELECT network_id,generation,revision FROM network WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, counter(r, 2)?)),
        )?;
        let generated_at = now() as u64;
        tx.commit()?;
        Ok(NetworkMap {
            protocol_version: PROTOCOL_VERSION,
            network_id,
            generation,
            revision,
            stun: None,
            generated_at,
            expires_at: generated_at + lease_seconds,
            user: owner,
            device: own,
            policy: own_policy,
            peers,
        })
    }
}
