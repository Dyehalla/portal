use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
const MAX_DEVICES: i64 = 4096;
const MAX_USER_DEVICES: i64 = 64;

pub(super) fn device(row: &Row<'_>) -> rusqlite::Result<Device> {
    let parse_error = |index, error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, error)
    };
    let ipv4: String = row.get(4)?;
    let ipv6: String = row.get(5)?;
    let endpoints: String = row.get(6)?;
    Ok(Device {
        id: row.get(0)?,
        owner_user_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        ipv4: ipv4.parse().map_err(|e| parse_error(4, Box::new(e)))?,
        ipv6: ipv6.parse().map_err(|e| parse_error(5, Box::new(e)))?,
        endpoints: serde_json::from_str(&endpoints).map_err(|e| parse_error(6, Box::new(e)))?,
        created_at: counter(row, 7)?,
    })
}

pub(super) fn authenticated_device(db: &Connection, credential: Credential) -> Result<Device> {
    if credential.role != Role::Device {
        return Err(Error::unauthorized());
    }
    db.query_row(
        &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE token_hash=? AND revoked=0"),
        [credential.hash.as_slice()],
        device,
    )
    .optional()?
    .ok_or_else(Error::unauthorized)
}

impl Store {
    pub fn register_device(
        &mut self,
        credential: Credential,
        request: RegisterDevice,
    ) -> Result<RegisteredDevice> {
        let name = name(&request.name)?;
        let public_key = public_key(&request.public_key)?;
        let endpoints = endpoints(request.endpoints)?;
        let tx = self.connection.transaction()?;
        let owner = authenticated_user(&tx, credential)?;
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let owned: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE owner_user_id=? AND revoked=0",
            [&owner.id],
            |r| r.get(0),
        )?;
        if total >= MAX_DEVICES || owned >= MAX_USER_DEVICES {
            return Err(Error::conflict("device limit reached"));
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE public_key=?)",
            [&public_key],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::conflict(
                "WireGuard public key is already registered",
            ));
        }
        let slot: u32 =
            tx.query_row("SELECT next_slot FROM network WHERE id=1", [], |r| r.get(0))?;
        let ipv4 = u32::from(self.ipv4.network())
            .checked_add(slot)
            .map(Ipv4Addr::from)
            .ok_or_else(|| Error::conflict("address pool exhausted"))?;
        if ipv4 >= self.ipv4.broadcast() {
            return Err(Error::conflict("address pool exhausted"));
        }
        let ipv6 = Ipv6Addr::from(u128::from(self.ipv6.network()) + u128::from(slot));
        let timestamp = now();
        let device = Device {
            id: format!("d_{}", credentials::random_hex(16)),
            owner_user_id: owner.id,
            name,
            public_key,
            ipv4,
            ipv6,
            endpoints,
            created_at: timestamp as u64,
        };
        let (access_token, hash) = credentials::issue(Role::Device);
        tx.execute("INSERT INTO devices(id,owner_user_id,name,public_key,token_hash,ipv4,ipv6,endpoints,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            params![device.id,device.owner_user_id,device.name,device.public_key,hash.as_slice(),
                device.ipv4.to_string(),device.ipv6.to_string(),serde_json::to_string(&device.endpoints).map_err(|_| Error::internal())?,timestamp])?;
        tx.execute("UPDATE network SET next_slot=next_slot+1 WHERE id=1", [])?;
        bump(&tx)?;
        tx.commit()?;
        Ok(RegisteredDevice {
            device,
            access_token,
        })
    }

    pub fn own_device(&self, credential: Credential) -> Result<Device> {
        authenticated_device(&self.connection, credential)
    }

    pub fn devices(&self, credential: Credential) -> Result<Vec<Device>> {
        let owner = authenticated_user(&self.connection, credential)?;
        let mut query = self.connection.prepare(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE owner_user_id=? AND revoked=0 ORDER BY id"
        ))?;
        Ok(query
            .query_map([owner.id], device)?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn revoke_device(&mut self, credential: Credential, id: &str) -> Result<()> {
        let tx = self.connection.transaction()?;
        let owner = authenticated_user(&tx, credential)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=? AND owner_user_id=?)",
            params![id, owner.id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::not_found());
        }
        if tx.execute(
            "UPDATE devices SET revoked=1 WHERE id=? AND revoked=0",
            [id],
        )? > 0
        {
            bump(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn rotate_device_token(&mut self, credential: Credential, id: &str) -> Result<IssuedToken> {
        let tx = self.connection.transaction()?;
        let owner = authenticated_user(&tx, credential)?;
        let (access_token, hash) = credentials::issue(Role::Device);
        if tx.execute(
            "UPDATE devices SET token_hash=? WHERE id=? AND owner_user_id=? AND revoked=0",
            params![hash.as_slice(), id, owner.id],
        )? == 0
        {
            return Err(Error::not_found());
        }
        bump(&tx)?;
        tx.commit()?;
        Ok(IssuedToken { access_token })
    }

    pub fn update_endpoints(
        &mut self,
        credential: Credential,
        request: UpdateEndpoints,
    ) -> Result<Device> {
        let endpoints = endpoints(request.endpoints)?;
        let tx = self.connection.transaction()?;
        let mut device = authenticated_device(&tx, credential)?;
        if device.endpoints != endpoints {
            device.endpoints = endpoints;
            tx.execute(
                "UPDATE devices SET endpoints=? WHERE id=?",
                params![
                    serde_json::to_string(&device.endpoints).map_err(|_| Error::internal())?,
                    device.id
                ],
            )?;
            bump(&tx)?;
        }
        tx.commit()?;
        Ok(device)
    }
}
