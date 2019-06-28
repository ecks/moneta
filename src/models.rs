use diesel::{self, prelude::*};

mod schema {
    table! {
        sessions (id) {
            id -> Nullable<Integer>,
            sess_id -> Integer,
        }
    }
}

use self::schema::sessions;
use self::schema::sessions::dsl::{sessions as all_sessions};

#[table_name="sessions"]
#[derive(Queryable, Insertable, Debug, Clone)]
pub struct Session {
    pub id: Option<i32>,
    pub sess_id: i32
}

impl Session {
    pub fn all(conn: &SqliteConnection) -> Vec<Session> {
        all_sessions.order(sessions::id.desc()).load::<Session>(conn).unwrap()
    }
}
