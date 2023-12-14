use dotenv::dotenv;
use hex::{encode, ToHex};
use md5;
use rand::RngCore;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime};
use subtle;
fn main() {
    dotenv().ok();
    let username = env::var("USERNAME").unwrap_or("btest".to_owned());
    let password: String = env::var("PASSWORD").unwrap_or("btest".to_owned());
    let require_auth = env::var("AUTH")
        .unwrap_or("true".to_owned())
        .parse::<bool>()
        .unwrap_or(true);
    let mut authisvalid = false;
    let udp_port_offset = 256;
    let btestport = 2000;
    let listener =
        TcpListener::bind(format!("0.0.0.0:{}", btestport)).expect("Failed to bind socket");
    println!("Server waiting for client connection on port 2000");

    for stream in listener.incoming() {
        match stream {
            Ok(mut client) => {
                let client_address = client.peer_addr().expect("Failed to get client address");
                println!("Connection from {}", client_address);

                // Sending hello
                let data = vec![0x01, 0x00, 0x00, 0x00];
                client.write_all(&data).expect("Failed to send data");

                // Reading reply
                let mut buffer = [0; 1024];
                client.read(&mut buffer).expect("Failed to read data");
                let action = unpack_cmd(&buffer);
                println!("{:?}", action.clone());
                // Send auth requested command
                if require_auth {
                    // Sending Data
                    client
                        .write_all(&hex::decode("02000000").expect("Failed to decode hex"))
                        .expect("Failed to send data");

                    // Setting Digest
                    let randomdigest = generate_random_array();
                    // Sending empty_array Digest
                    client
                        .write_all(&randomdigest)
                        .expect("Failed to send digest");

                    // Receiving Data
                    let mut data = [0u8; 1024];
                    client.read(&mut data).expect("Failed to receive data");

                    // Printing Data
                    let currentpasshash = hash_gen(&password, randomdigest);
                    let receivedpasshash = hex::encode(&data[0..16]);
                    let mut receivedusername = String::from_utf8_lossy(&data[16..100]).to_string();
                    receivedusername.retain(|c| c.is_ascii_alphanumeric());
                    let currentusername = username.clone();
                    let isvaid = receivedusername.eq(&currentusername)
                        && receivedpasshash.eq(&currentpasshash);
                    authisvalid = isvaid.clone();
                    println!(
                        "- client auth data is : username {}, password digest: {:?}",
                        receivedusername, receivedpasshash
                    );
                    // println!(
                    //     "- server auth data is : username {}, password digest: {:?}",
                    //     username, currentpasshash
                    // );
                    println!("is credentials valid: {}", isvaid);
                    // Sending Authentication Acceptance
                    match isvaid {
                        true => {
                            client
                                .write_all(&hex::decode("01000000").expect("Failed to decode hex"))
                                .expect("Failed to send acceptance");
                        }
                        false => {
                            client
                                .write_all(&hex::decode("00000000").expect("Failed to decode hex"))
                                .expect("Failed to send acceptance");
                        }
                    }
                }
                
                if !require_auth || authisvalid {
                    println!("Sending hello");
                        // Sending hello
                    let data = vec![0x01, 0x00, 0x00, 0x00];
                    client.write_all(&data).expect("Failed to send data");
                    if action.proto == "TCP" {
                        // Send TCP socket port
                        // Establish TCP socket
                        // Send TCP data
                        todo!()
                    } else {
                        // Send UDP socket port
                        // Establish UDP socket
                        // Send UDP data
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to establish a connection: {}", e);
            }
        }
    }
}
fn generate_random_array() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut random_array: [u8; 16] = [0; 16]; // Initialize with zeros
    rng.fill_bytes(&mut random_array);
    random_array
}
struct CmdStruct {
    tx_size: usize,
}
#[derive(Debug, Default, Clone)]
struct RecvStats {
    recv_bytes: u64,
    max_interval: u64,
    min_interval: u64,
    lost_packets: u64,
}

impl RecvStats {
    fn new() -> RecvStats {
        RecvStats {
            recv_bytes: 0,
            max_interval: 0,
            min_interval: 0,
            lost_packets: 0,
        }
    }
}
fn test_udp_rx(udp_socket: &UdpSocket, cmd: &CmdStruct) {
    let mut recv_stats = RecvStats::new();
    let mut buf = vec![0; cmd.tx_size];
    let mut last = SystemTime::now();
    let mut last_seq = 0;
    let _ = udp_socket.set_write_timeout(Some(Duration::from_secs(30)));
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((n_bytes, saddress)) => {
                let now = SystemTime::now();
                let this_seq = (buf[0] as u64) << 24
                    | (buf[1] as u64) << 16
                    | (buf[2] as u64) << 8
                    | buf[3] as u64;

                if last_seq > 0 {
                    recv_stats.lost_packets += this_seq - last_seq - 1;
                }

                if last != SystemTime::UNIX_EPOCH {
                    let interval = now
                        .duration_since(last)
                        .unwrap_or_else(|_| Duration::from_secs(0));
                    let interval_us = interval.as_micros();

                    if recv_stats.max_interval == 0 {
                        recv_stats.max_interval = interval_us as u64;
                        recv_stats.min_interval = interval_us as u64;
                    } else {
                        if interval_us > recv_stats.max_interval.into() {
                            recv_stats.max_interval = interval_us as u64;
                        }
                        if interval_us < recv_stats.min_interval.into() {
                            recv_stats.min_interval = interval_us as u64;
                        }
                    }
                }
                last = now;
                recv_stats.recv_bytes += n_bytes as u64;
                print!("{:?}", recv_stats);
                last_seq = this_seq;
            }
            Err(_) => {
                // Ignore connection refused - the other end probably wasn't ready
                print!(
                    "{}",
                    "Ignore connection refused - the other end probably wasn't ready"
                );
                // Handle other errors as needed
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Action {
    proto: String,
    direction: String,
    random: bool,
    tcp_conn_count: u8,
    tx_size: u16,
    unknown: u32,
    remote_tx_speed: u32,
    local_tx_speed: u32,
}

fn unpack_cmd(data: &[u8]) -> Action {
    let cmd_list: Vec<u8> = data.iter().cloned().collect();
    let cmd = Action {
        proto: if cmd_list[0] != 0 {
            "TCP".to_string()
        } else {
            "UDP".to_string()
        },
        direction: match cmd_list[1] {
            1 => "RX".to_string(),
            2 => "TX".to_string(),
            _ => "TXRX".to_string(),
        },
        random: cmd_list[2] == 0,
        tcp_conn_count: if cmd_list[3] == 0 { 1 } else { cmd_list[3] },
        tx_size: u16::from_be_bytes([cmd_list[4], cmd_list[5]]),
        unknown: u32::from_be_bytes([cmd_list[6], cmd_list[7], cmd_list[8], cmd_list[9]]),
        remote_tx_speed: u32::from_be_bytes([
            cmd_list[10],
            cmd_list[11],
            cmd_list[12],
            cmd_list[13],
        ]),
        local_tx_speed: u32::from_be_bytes([
            cmd_list[14],
            cmd_list[15],
            cmd_list[16],
            cmd_list[17],
        ]),
    };
    cmd
}

pub fn hash_gen(input_password: &str, nonce: [u8; 16]) -> String {
    // Create an MD5 hasher
    let mut hash: [u8; 16];
    let mut md5 = md5::Context::new();
    md5.consume(input_password);
    md5.consume(nonce);
    hash = md5.compute().0;
    md5 = md5::Context::new();
    md5.consume(input_password);
    md5.consume(hash);
    hash = md5.compute().0;
    // Obtain the hexadecimal representation of the computed MD5 hash
    let computed_md5_hex = hex::encode(hash);
    computed_md5_hex
}

#[test]
fn decrypt() {
    // Convert bytes to a string
    let input_password = "admin"; // Replace this with the password you want to validate

    // Validate the password
    // calc_md5auth = calc_md5auth(input_password, saved_password_md5_hex);
    println!("Password: {}",);
}
