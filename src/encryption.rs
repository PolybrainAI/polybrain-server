use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use block_modes::Cbc;
use hex::{decode, encode};
use sha2::{Digest, Sha256};

// Type alias to simplify the code for using CBC mode with AES and Pkcs7 padding.
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn generate_key_iv() -> ([u8; 16], [u8; 16]) {
    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");

    // Hash the secret key using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(secret_key);
    let hash_result = hasher.finalize();

    // Take the first 16 bytes of the hash as the key
    let key = {
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash_result[..16]);
        key
    };

    // Take the next 16 bytes of the hash as the IV
    let iv = {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&hash_result[16..32]);
        iv
    };

    (key, iv)
}

pub fn encrypt(data: &[u8]) -> String {
    let (key, iv) = generate_key_iv();
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).expect("Failed to process cipher");
    let ciphertext = cipher.encrypt_vec(data);

    // Encode ciphertext as hexadecimal and prepend IV in hex for simplicity
    encode(iv) + &encode(&ciphertext)
}

pub fn decrypt(encrypted_data: &str) -> String {
    let (key, _) = generate_key_iv();
    let encrypted_data = decode(encrypted_data).unwrap();
    let (iv, encrypted_data) = encrypted_data.split_at(16);
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).expect("Failed to process cipher");
    let decrypted_data = cipher
        .decrypt_vec(encrypted_data)
        .expect("Failed to decrypt key: decrypt_vec failed");

    String::from_utf8(decrypted_data).expect("Failed to decrypt key: could not assemble UTF-8")
}
