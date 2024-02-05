use dotenv::dotenv;
use md5;
use rand::RngCore;
use std::env;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use tokio::io::AsyncWriteExt;

use crate::constants::MESSAGE_PREFIX;
mod constants;
mod utils;

#[tokio::main]
async fn main() {
    let mut _store = constants::Store {
        current_port: constants::btestport,
    };
    dotenv().ok();
    let username = env::var("USERNAME").unwrap_or("btest".to_owned());
    let password: String = env::var("PASSWORD").unwrap_or("btest".to_owned());
    let require_auth = env::var("AUTH")
        .unwrap_or("true".to_owned())
        .parse::<bool>()
        .unwrap_or(true);
    let mut authisvalid = false;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", constants::btestport))
        .expect("Failed to bind socket");
    println!(
        "Server waiting for client connection on port {}",
        constants::btestport
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut client) => {
                let client_address = client.peer_addr().expect("Failed to get client address");
                println!("Connection from {}", client_address);
                // Sending hello
                client
                    .write_all(&hex::decode("01000000").unwrap())
                    .expect("Failed to send data");
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
                    let randomdigest = utils::generate_random_array();
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
                    client
                        .write(&hex::decode("01000000").unwrap_or_default())
                        .expect("Failed to send data");
                    if action.proto == "TCP" {
                        tokio::spawn(handle_tcp(client, action.tx_size, action));
                        // Send TCP socket port
                        // Establish TCP socket
                        // Send TCP data
                    } else {
                        // send ready message:
                        // Send UDP data
                        let mut buffer = [0; 32];
                        let mut bufport: Vec<u8> = Vec::with_capacity(2);
                        _store.current_port += 1;
                        bufport.push((_store.current_port / constants::udp_port_offset) as u8);
                        bufport.push((_store.current_port % constants::udp_port_offset) as u8);
                        if let Ok(_) = client.read(&mut buffer) {
                            client.write(&bufport).expect("Failed to send data");
                            let addrs = [
                                SocketAddr::from((
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                                    _store.current_port,
                                )),
                                SocketAddr::from((
                                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                    )),
                                    _store.current_port,
                                )),
                            ];
                            if let Ok(sock) = UdpSocket::bind(&addrs[..]) {
                                let _ = sock.set_nonblocking(true);
                                let _ = sock.set_broadcast(true);
                                let _ = sock.set_multicast_ttl_v4(42);
                                let _ = sock.set_ttl(42);
                                println!(
                                    "Server waiting for udp packets on port {}\n",
                                    _store.current_port
                                );
                                tokio::spawn(handle_udp(sock, action, client_address));
                            };
                        } else {
                            client
                                .write_all(&hex::decode("00000000").expect("Failed to decode hex"))
                                .expect("Failed to send acceptance");
                        };
                    }
                }
            }
            Err(e) => {
                println!("Failed to establish a connection: {}", e);
            }
        }
    }
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
async fn handle_tcp(mut socket: std::net::TcpStream, tx_size: u16, action: Action) -> Result<String, String>{
    println!("Connection established");
    socket
        .write(&hex::decode("01000000").unwrap_or_default())
        .expect("Failed to send data");
    print!("tx_size={:?}\n", tx_size);
    // socket
    //     .write(&hex::decode("01080000").unwrap_or_default())
    //     .expect("Failed to send data");
    let mut seq: u32 = 1;
    let mut err_count: u64 = 0;
    loop {
        // recv from remote_addr
        let mut buf = vec![0; action.tx_size.into()];
        // Pack the data into a binary packet
        seq += 1;
        if let Err(err) = socket.write(&buf) {
            err_count += 1;
            println!("error send: {} number: {}", err.to_string(), err_count)
        };
        if let Ok(_) = socket.read(&mut buf) {
            let mut seqbytes = [0u8; 4];
            let _ = (0..3).map(|idx| {
                seqbytes[idx] = buf[idx];
                idx
            });
            print!(
                "recv from tcpclient packet buf: {} / {}\n",
                u32::from_le_bytes(seqbytes),
                seq.to_string()
            );
        } else {
            err_count += 1;
        };
        if err_count > action.tx_size.into() {
            return Ok("done!".to_string());
        }
    }
}
async fn handle_udp(
    socket: UdpSocket,
    action: Action,
    client_address: SocketAddr,
) -> Result<String, String> {
    let mut udpclient = client_address.clone();
    let myaddress = socket.local_addr().unwrap();
    println!("udp socket address: {}", myaddress.to_string());
    udpclient.set_port(myaddress.port() + constants::udp_port_offset);
    match socket.connect(udpclient) {
        Ok(_) => {
            print!("udp socket connected to {}\n", udpclient);
            let mut seq: u64 = 0;
            let tx_size: usize = action.tx_size.into();
            // let zeros_vec: Vec<u8> = vec![0; 1024];
            // let _ = socket.send(&zeros_vec).await;
            let mut err_count: u64 = 0;
            loop {
                // let message: [u8; MESSAGE_SIZE] =
                // [MESSAGE_PREFIX, 0, 0, 0, 1, 0, 0, 0, 54, 110, 3, 0];
                // recv from remote_addr

                let mut buf = vec![0; action.tx_size.into()];
                match action.direction.as_str() {
                    "TX" => {
                        let packet =
                            utils::generate_prefixed_bytes(seq, (action.tx_size - 28) as usize);
                        seq += 1;

                        if let Err(err) = socket.send(&packet) {
                            err_count += 1;
                            print!("error {} number: {}\n", err.to_string(), err_count);
                            if err_count > action.tx_size.into() {
                                return Ok("Done conunting error time to go out!".to_string());
                            }
                        };
                    }
                    "RX" => {
                        if let Ok(_) = socket.recv(&mut buf) {
                            seq += 1;
                            print!(
                                "recv from udpclient_addr packet buf: {} / {}\n",
                                buf.len(),
                                seq.to_string()
                            );
                        }
                    }
                    _ => {
                        let packet =
                            utils::generate_prefixed_bytes(seq, (action.tx_size - 28) as usize);
                        seq += 1;
                        if let Ok((r, address)) = socket.recv_from(&mut buf) {
                            // let _but = hex::decode(message).unwrap();
                            if r > 0 {
                                print!(
                                    "recv from udpclient_addr packet seq: {:?} from: {}\n",
                                    buf.split_at((3) as usize).0,
                                    address.to_string()
                                );
                            }
                        } else {
                            err_count += 1;
                        };
                        if let Ok(s) = socket.send(&packet) {
                            // Pack the values into the Vec<u8>
                            if s > 0 {
                                println!("sent packet len: {} in seq: {}", packet.len(), seq);
                            }
                        } else {
                            err_count += 1;
                        }
                    }
                };
                if err_count > action.tx_size.into() {
                    return Ok("done!".to_string());
                }
            }
        }
        Err(_) => {
            return Err(format!("udp socket faild to connect to {}", udpclient));
        }
    };
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
        tx_size: u16::from_le_bytes([cmd_list[4], cmd_list[5]]),
        unknown: u32::from_le_bytes([cmd_list[6], cmd_list[7], cmd_list[8], cmd_list[9]]),
        remote_tx_speed: u32::from_le_bytes([
            cmd_list[10],
            cmd_list[11],
            cmd_list[12],
            cmd_list[13],
        ]),
        local_tx_speed: u32::from_le_bytes([
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
    let mut seq: u64 = 1;
    loop {
        let message = utils::generate_prefixed_bytes(seq, 1500 - 28);
        seq += 1;
        println!("{:?}", message);
    }
}
