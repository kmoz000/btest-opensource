use rand::{Rng, RngCore};

pub fn generate_random_hex_with_sequence(sequence: u64, length: usize) -> String {
    // Generate a random hexadecimal string of bytes
    let random_hex: String = (0..length * 2)
        .map(|_| format!("{:X}", rand::thread_rng().gen_range(0..=15)))
        .collect();

    // Generate a 12-byte sequence prefix
    let sequence_prefix: String = format!("{:012X}", sequence);

    // Concatenate the sequence prefix and random_hex
    let result_hex = format!("{}{}", sequence_prefix, random_hex);

    result_hex
}
pub fn generate_prefixed_bytes(seq: u64, length: usize) -> Vec<u8> {
    // Create a Vec<u8> with the specified length and prefix
    // Extend the Vec with the provided prefix
    let mut trd = rand::thread_rng();
    let mut buf: Vec<u8> = vec![];
    let tmp = seq; // Replace with the actual value from your code
    buf.extend(vec![((((tmp / 256) / 256) / 256) % 256) as u8,(((tmp / 256) / 256) % 256) as u8, ((tmp / 256) % 256) as u8, (tmp % 256) as u8]);
    buf.extend((0..(length - 4)).map(|_| trd.gen::<u8>()));
    buf
}
pub fn generate_random_array() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut random_array: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut random_array);
    random_array
}