fn main() {
    let mut client = osquery_rs::ExtensionManagerClient::new().unwrap();
    let resp = client
        .query(String::from("SELECT * from USERS limit 1"))
        .unwrap();
    match resp.response {
        Some(res) => println!("Got results: {:?}", res),
        None => {
            println!(
                "osqueryd returned error: {:?}",
                resp.status.unwrap_or_default()
            );
            std::process::exit(1);
        }
    }
}
