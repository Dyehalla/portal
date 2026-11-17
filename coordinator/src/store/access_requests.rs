use super::*;

fn expire(db: &Connection) -> Result<()> {
    db.execute(
        "UPDATE access_requests SET status='expired' WHERE status='pending' AND expires_at<=?",
        [now()],
    )?;
    db.execute(
        "DELETE FROM access_requests WHERE status!='pending' AND created_at<?",
        [now() - 7 * 86400],
    )?;
    Ok(())
}

type StoredRequest = (String, String, String, String, bool, u64, u64, Option<i64>);

fn read(db: &Connection, id: &str) -> Result<AccessRequest> {
    let (source, target, tcp, status, terminal, created_at, expires_at, revision):
        StoredRequest = db.query_row(
        "SELECT source_id,target_id,tcp,status,terminal,created_at,expires_at,policy_revision FROM access_requests WHERE id=?",
        [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get::<_, i64>(4)? != 0,counter(r,5)?,counter(r,6)?,r.get(7)?)))
        .optional()?.ok_or_else(Error::not_found)?;
    let get_device = |id: &str| {
        db.query_row(
            &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id=? AND revoked=0"),
            [id],
            device,
        )
        .optional()?
        .ok_or_else(Error::not_found)
    };
    let source = get_device(&source)?;
    let target = get_device(&target)?;
    let requester_name = db.query_row(
        "SELECT name FROM users WHERE id=?",
        [&source.owner_user_id],
        |r| r.get(0),
    )?;
    Ok(AccessRequest {
        id: id.into(),
        source,
        target,
        requester_name,
        tcp: serde_json::from_str(&tcp).map_err(|_| Error::internal())?,
        terminal,
        status,
        created_at,
        expires_at,
        policy_revision: revision
            .map(u64::try_from)
            .transpose()
            .map_err(|_| Error::internal())?,
    })
}

impl Store {
    pub fn access_requests(&mut self, credential: Credential) -> Result<Vec<AccessRequest>> {
        let owner = authenticated_user(&self.connection, credential)?;
        expire(&self.connection)?;
        let ids = {
            let mut query = self.connection.prepare("SELECT r.id FROM access_requests r JOIN devices s ON s.id=r.source_id JOIN devices t ON t.id=r.target_id WHERE s.revoked=0 AND t.revoked=0 AND (s.owner_user_id=? OR t.owner_user_id=?) ORDER BY (r.status='pending') DESC,r.created_at DESC,r.id LIMIT 256")?;
            query
                .query_map(params![owner.id, owner.id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        ids.iter().map(|id| read(&self.connection, id)).collect()
    }

    pub fn request_access(
        &mut self,
        credential: Credential,
        request: RequestAccess,
    ) -> Result<AccessRequest> {
        let tx = self.connection.transaction()?;
        let owner = authenticated_user(&tx, credential)?;
        expire(&tx)?;
        let source = tx.query_row(&format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id=? AND owner_user_id=? AND revoked=0"), params![request.source_device_id,owner.id], device).optional()?.ok_or_else(Error::not_found)?;
        let target = tx
            .query_row(
                &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id=? AND revoked=0"),
                [&request.target_device_id],
                device,
            )
            .optional()?
            .ok_or_else(Error::not_found)?;
        if source.owner_user_id == target.owner_user_id {
            return Err(Error::bad_request(
                "edit permissions of your own device directly",
            ));
        }
        let ports = validate::tcp_ports(request.tcp)?;
        if ports.is_empty() && !request.terminal {
            return Err(Error::bad_request(
                "request at least one TCP port or terminal access",
            ));
        }
        let existing: Option<String> = tx.query_row("SELECT id FROM access_requests WHERE source_id=? AND target_id=? AND status='pending'", params![source.id,target.id], |r|r.get(0)).optional()?;
        if let Some(id) = existing {
            let old = read(&tx, &id)?;
            if old.tcp != ports || old.terminal != request.terminal {
                return Err(Error::conflict(
                    "a request for this device is already pending",
                ));
            }
            tx.commit()?;
            return Ok(old);
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM access_requests r JOIN devices s ON s.id=r.source_id WHERE s.owner_user_id=? AND r.created_at>?", params![owner.id,now()-86400], |r|r.get(0))?;
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM access_requests", [], |r| r.get(0))?;
        if count >= 64 || total >= 4096 {
            return Err(Error::conflict("access request limit reached"));
        }
        let id = format!("a_{}", credentials::random_hex(16));
        tx.execute("INSERT INTO access_requests(id,source_id,target_id,tcp,terminal,status,created_at,expires_at) VALUES(?,?,?,?,?,'pending',?,?)", params![id,source.id,target.id,serde_json::to_string(&ports).map_err(|_|Error::internal())?,request.terminal,now(),now()+86400])?;
        let result = read(&tx, &id)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn decide_access(
        &mut self,
        credential: Credential,
        id: &str,
        accept: bool,
    ) -> Result<AccessRequest> {
        let tx = self.connection.transaction()?;
        let owner = authenticated_user(&tx, credential)?;
        let request = read(&tx, id)?;
        if request.target.owner_user_id != owner.id {
            return Err(Error::not_found());
        }
        if request.status != "pending" {
            if (request.status == "accepted" && accept) || (request.status == "declined" && !accept)
            {
                return Ok(request);
            }
            return Err(Error::conflict("request already answered"));
        }
        if request.expires_at <= now() as u64 {
            return Err(Error::conflict("request expired"));
        }
        let revision = if accept {
            let current = policy::desired(&tx, &request.target.id)?;
            let (base_revision, mut permissions) = match current {
                Some(p) => (p.revision, p.permissions),
                None => {
                    let p = policy(&tx, &request.target.id)?;
                    (p.revision, p.permissions)
                }
            };
            let entry = permissions
                .entry(request.source.public_key.clone())
                .or_default();
            entry.tcp.extend(&request.tcp);
            entry.terminal |= request.terminal;
            entry.tcp.sort_unstable();
            entry.tcp.dedup();
            Some(
                policy::write_owner_policy(
                    &tx,
                    &request.target,
                    PublishPolicy {
                        base_revision,
                        permissions,
                    },
                )?
                .revision,
            )
        } else {
            None
        };
        tx.execute(
            "UPDATE access_requests SET status=?,policy_revision=? WHERE id=?",
            params![
                if accept { "accepted" } else { "declined" },
                revision
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|_| Error::internal())?,
                id
            ],
        )?;
        let result = read(&tx, id)?;
        tx.commit()?;
        Ok(result)
    }
}
