use super::*;

impl Store {
    pub fn network_map(
        &mut self,
        credential: Credential,
        lease_seconds: u64,
    ) -> Result<NetworkMap> {
        let tx = self.connection.transaction()?;
        let own = authenticated_device(&tx, credential)?;
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
                if !incoming.tcp.is_empty() || !outgoing.tcp.is_empty() {
                    peers.push(Peer {
                        device: candidate,
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
            generated_at,
            expires_at: generated_at + lease_seconds,
            user: owner,
            device: own,
            policy: own_policy,
            peers,
        })
    }
}
