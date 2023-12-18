use dotenv::dotenv;
use hex::{encode, ToHex};
use md5;
use rand::RngCore;
use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, SystemTime};
use subtle;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::{net::UdpSocket, sync::mpsc};
const MESSAGE_PREFIX: u8 = 0x07;
const MESSAGE_SIZE: usize = 12;
#[tokio::main]
async fn main() {
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
                    client
                        .write_all(&hex::decode("01000000").unwrap_or_default())
                        .expect("Failed to send data");
                    if action.proto == "TCP" {
                        tokio::spawn(handle_tcp(client, action.tx_size));
                        // Send TCP socket port
                        // Establish TCP socket
                        // Send TCP data
                        // todo!()
                    } else {
                        // send ready message:
                        // Send UDP data
                        let udpport: u16 = udp_port_offset;
                        let mut buffer = [0; 32];
                        if let Ok(len) = client.read(&mut buffer) {
                            // print!("buffer : {:?} size of {}\n", buffer, len);
                            client
                                .write_all(&udpport.to_ne_bytes())
                                .expect("Failed to send data");
                            if let Ok(sock) = UdpSocket::bind(format!("0.0.0.0:{}", udp_port_offset)).await {
                                println!("Server listening on port 2001...");
                                let mut udpclient = client_address.clone();
                                udpclient.set_port(udp_port_offset * 2);
                                match sock.connect(udpclient).await {
                                    Ok(_) => {
                                        print!("udp socket connected to {}", udpclient);
                                        let mut seq: u32 = 1;
                                        loop {
                                            // let message: [u8; MESSAGE_SIZE] =
                                                // [MESSAGE_PREFIX, 0, 0, 0, 1, 0, 0, 0, 54, 110, 3, 0];
                                            // recv from remote_addr
                                            let mut buf = vec![0; 12];
                                            // Pack the data into a binary packet
                                            
                                            if let Ok(len) = sock.recv(&mut buf).await {
                                                if let Ok(len) = sock.send(&mut buf).await {
                                                    if len > 0 {
                                                        seq += 1;
                                                    }
                                                    print!("sent to udpclient_addr packet buf: {}\n", len);
                                                };
                                                print!(
                                                    "recv from udpclient_addr packet buf: {} / {}\n",
                                                    hex::encode(&buf),
                                                    len
                                                );
                                            };
                                            // handle_udp(&sock, action.tx_size).await;
                                        }
                                    }
                                    Err(_) => {
                                        print!("udp socket faild to connect to {}", udpclient);
                                    }
                                };
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
async fn handle_tcp(mut socket: std::net::TcpStream, tx_size: u16) {
    println!("Connection established");
    let hello = [0x01, 0x00, 0x00, 0x00];
    socket.write_all(&hello).unwrap();
    print!("tx_size={:?}", tx_size);
    // loop {
    //     let data = vec![0u8; tx_size.into()]; // Adjust the size as needed
    //     socket.write_all(&data).await.unwrap();
    //     println!("Sent data");
    // }
}
async fn handle_udp(socket: &UdpSocket, tx_size: u16) {
    let hello = [0x01, 0x00, 0x00, 0x00];
    let _ = socket.send(&hello).await.unwrap();
    let mut buf = Vec::with_capacity(tx_size.into());
    let _ = socket.send(&mut buf).await.unwrap();
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
    let sendport = hex::encode(2001_u16.to_be_bytes());
}
