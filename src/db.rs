use rocket_contrib::databases::diesel;

use diesel::SqliteConnection;

#[database("sqlite_database")]
pub struct DbConn(SqliteConnection);

