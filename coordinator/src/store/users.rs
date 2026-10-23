use super::*;
const MAX_USERS: i64 = 1024;

pub(super) fn user(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        name: row.get(1)?,
        is_admin: row.get(2)?,
        created_at: counter(row, 3)?,
    })
}

pub(super) fn authenticated_user(db: &Connection, credential: Credential) -> Result<User> {
    if credential.role != Role::User {
        return Err(Error::unauthorized());
    }
    db.query_row(
        &format!("SELECT {USER_COLUMNS} FROM users WHERE token_hash=?"),
        [credential.hash.as_slice()],
        user,
    )
    .optional()?
    .ok_or_else(Error::unauthorized)
}

impl Store {
    pub fn register_user(&mut self, request: RegisterUser) -> Result<RegisteredUser> {
        let name = name(&request.name)?;
        let tx = self.connection.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if count >= MAX_USERS {
            return Err(Error::conflict("user limit reached"));
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name=?)",
            [&name],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::conflict("user name is already registered"));
        }
        let timestamp = now();
        let user = User {
            id: format!("u_{}", credentials::random_hex(16)),
            name,
            is_admin: false,
            created_at: timestamp as u64,
        };
        let (access_token, hash) = credentials::issue(Role::User);
        tx.execute(
            "INSERT INTO users(id,name,token_hash,created_at) VALUES(?,?,?,?)",
            params![user.id, user.name, hash.as_slice(), timestamp],
        )?;
        bump(&tx)?;
        tx.commit()?;
        Ok(RegisteredUser { user, access_token })
    }

    pub fn me(&self, credential: Credential) -> Result<User> {
        authenticated_user(&self.connection, credential)
    }

    pub fn find_user(&self, credential: Credential, requested_name: &str) -> Result<User> {
        authenticated_user(&self.connection, credential)?;
        self.connection
            .query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE name=?"),
                [name(requested_name)?],
                user,
            )
            .optional()?
            .ok_or_else(Error::not_found)
    }
}
