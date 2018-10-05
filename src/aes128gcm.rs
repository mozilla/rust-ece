/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, ByteOrder};
use common::*;
use ece_crypto::Crypto;
use error::*;
use CryptoImpl;

const ECE_AES128GCM_MIN_RS: u32 = 18;
const ECE_AES128GCM_HEADER_LENGTH: usize = 21;
const ECE_AES128GCM_MAX_KEY_ID_LENGTH: usize = 255;
const ECE_AES128GCM_PAD_SIZE: usize = 1;

const ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX: &'static str = "WebPush: info\0";
const ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH: usize = 144; // 14 (prefix len) + 65 (pub key len) * 2;

const ECE_WEBPUSH_IKM_LENGTH: usize = 32;
const ECE_AES128GCM_KEY_INFO: &'static str = "Content-Encoding: aes128gcm\0";
const ECE_AES128GCM_NONCE_INFO: &'static str = "Content-Encoding: nonce\0";

/// Decrypts a Web Push message encrypted using the "aes128gcm" scheme.
pub fn decrypt(raw_local_prv_key: &[u8], auth_secret: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let params = ece_aes128gcm_payload_extract_params(payload)?;
    return Aes128GcmEceWebPush::decrypt(
        raw_local_prv_key,
        params.header.key_id,
        auth_secret,
        params.header.salt,
        params.header.rs,
        params.ciphertext,
    );
}

// TODO: When done, remove the aes128gcm prefixes and the EC_ ones.
// As for now it makes it easier to Ctrl + F into ecec :)

struct Aes128GcmEceWebPush;
impl EceWebPush for Aes128GcmEceWebPush {
    /// Always returns false because "aes128gcm" uses
    /// a padding scheme that doesn't need a trailer.
    fn needs_trailer(_: u32, _: usize) -> bool {
        return false;
    }

    // Make sure to check that `plaintext.len() < PAD_SIZE` in the implementation.
    fn unpad(block: &[u8], last_record: bool) -> Result<&[u8]> {
        if block.len() < ECE_AES128GCM_PAD_SIZE {
            return Err(ErrorKind::BlockTooShort.into());
        }
        let pos = match block.iter().rposition(|&b| b != 0) {
            Some(pos) => pos,
            None => return Err(ErrorKind::ZeroCiphertext.into()),
        };
        let expected_delim = if last_record { 2 } else { 1 };
        if block[pos] != expected_delim {
            return Err(ErrorKind::DecryptPadding.into());
        }
        return Ok(&block[..pos]);
    }

    /// Derives the "aes128gcm" decryption key and nonce given the receiver private
    /// key, sender public key, authentication secret, and sender salt.
    fn webpush_derive_key_and_nonce(
        ece_mode: EceMode,
        raw_local_prv_key: &[u8],
        raw_remote_pub_key: &[u8],
        auth_secret: &[u8],
        salt: &[u8],
    ) -> Result<KeyAndNonce> {
        // TODO: we should probably do this all at once in Crypto and send back some structure containing 4 buffers!
        let shared_secret = CryptoImpl::compute_ecdh_secret(raw_local_prv_key, raw_remote_pub_key)?;
        let raw_local_pub_key = CryptoImpl::ec_prv_uncompressed_point(raw_local_prv_key)?;

        // The new "aes128gcm" scheme includes the sender and receiver public keys in
        // the info string when deriving the Web Push IKM.
        let ikm_info = match ece_mode {
            EceMode::ENCRYPT => {
                ece_webpush_aes128gcm_generate_info(raw_remote_pub_key, &raw_local_pub_key)
            }
            EceMode::DECRYPT => {
                ece_webpush_aes128gcm_generate_info(&raw_local_pub_key, raw_remote_pub_key)
            }
        }?;
        let ikm = CryptoImpl::hkdf_sha256(
            auth_secret,
            &shared_secret,
            &ikm_info,
            ECE_WEBPUSH_IKM_LENGTH,
        )?;
        ece_aes128gcm_derive_key_and_nonce(salt, &ikm)
    }
}

/// Derives the "aes128gcm" content encryption key and nonce.
fn ece_aes128gcm_derive_key_and_nonce(salt: &[u8], ikm: &[u8]) -> Result<KeyAndNonce> {
    let key = CryptoImpl::hkdf_sha256(
        salt,
        ikm,
        ECE_AES128GCM_KEY_INFO.as_bytes(),
        ECE_AES_KEY_LENGTH,
    )?;
    let nonce = CryptoImpl::hkdf_sha256(
        salt,
        ikm,
        ECE_AES128GCM_NONCE_INFO.as_bytes(),
        ECE_NONCE_LENGTH,
    )?;
    Ok((key, nonce))
}

// The "aes128gcm" IKM info string is "WebPush: info\0", followed by the
// receiver and sender public keys.
fn ece_webpush_aes128gcm_generate_info(
    raw_recv_pub_key: &[u8],
    raw_sender_pub_key: &[u8],
) -> Result<[u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH]> {
    let mut info = [0u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH];
    let prefix = ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX.as_bytes();
    let mut offset = prefix.len();
    info[0..offset].copy_from_slice(prefix);
    info[offset..offset + ECE_WEBPUSH_PUBLIC_KEY_LENGTH].copy_from_slice(raw_recv_pub_key);
    offset += ECE_WEBPUSH_PUBLIC_KEY_LENGTH;
    info[offset..].copy_from_slice(raw_sender_pub_key);
    Ok(info)
}

/// Extracts "aes128gcm" decryption parameters from an encrypted payload.
fn ece_aes128gcm_payload_extract_params(payload: &[u8]) -> Result<DecryptionParams> {
    if payload.len() < ECE_AES128GCM_HEADER_LENGTH {
        return Err(ErrorKind::HeaderTooShort.into());
    }

    let key_id_len = payload[ECE_SALT_LENGTH + 4] as usize;
    if payload.len() < ECE_AES128GCM_HEADER_LENGTH + key_id_len {
        return Err(ErrorKind::HeaderTooShort.into());
    }

    let rs = BigEndian::read_u32(&payload[ECE_SALT_LENGTH..]);
    if rs < ECE_AES128GCM_MIN_RS {
        return Err(ErrorKind::InvalidRecordSize.into());
    }

    let salt = &payload[0..ECE_SALT_LENGTH];
    if key_id_len != ECE_WEBPUSH_PUBLIC_KEY_LENGTH {
        return Err(ErrorKind::InvalidKeyLength.into());
    }
    let key_id_pos = ECE_AES128GCM_HEADER_LENGTH;
    let key_id = &payload[key_id_pos..key_id_pos + key_id_len];

    let ciphertext_start = ECE_AES128GCM_HEADER_LENGTH + key_id_len;
    if payload.len() == ciphertext_start {
        return Err(ErrorKind::ZeroCiphertext.into());
    }
    let ciphertext = &payload[ciphertext_start..];
    Ok(DecryptionParams {
        ciphertext,
        header: Header { salt, rs, key_id },
    })
}

struct DecryptionParams<'a> {
    ciphertext: &'a [u8],
    header: Header<'a>,
}

struct Header<'a> {
    pub salt: &'a [u8],
    pub rs: u32,
    pub key_id: &'a [u8],
}

#[cfg(test)]
mod tests {
    extern crate hex;
    use super::*;

    fn try_decrypt(priv_key: &str, auth_secret: &str, payload: &str) -> Result<String> {
        let priv_key = hex::decode(priv_key).unwrap();
        let auth_secret = hex::decode(auth_secret).unwrap();
        let payload = hex::decode(payload).unwrap();
        let plaintext = decrypt(&priv_key, &auth_secret, &payload)?;
        Ok(String::from_utf8(plaintext).unwrap())
    }

    #[test]
    fn test_rs_24_pad_0() {
        let plaintext = try_decrypt(
            "c899d11d32e2b7e6fe7498786f50f23b98ace5397ad261de39ba6449ecc12cad",
            "996fad8b50aa2d02b83f26412b2e2aee",
            "495ce6c8de93a4539e862e8634993cbb0000001841043c3378a2c0ab954e1498718e85f08bb723fb7d25e135a663fe385884eb8192336bf90a54ed720f1c045c0b405e9bbc3a2142b16c89086734c374ebaf7099e6427e2d32c8ada5018703c54b10b481e1027d7209d8c6b43553fa133afa597f2ddc45a5ba8140944e6490bb8d6d99ba1d02e60d95f48ce644477c17231d95b97a4f95dd"
        ).unwrap();
        assert_eq!(plaintext, "I am the walrus");
    }

    #[test]
    fn test_rs_49_pad_84_ciphertext_len_falls_on_record_boundary() {
        let plaintext = try_decrypt(
            "67004a4ea820deed8e49db5e9480e63d3ea3cce1ae8e1a60609713d527d001ef",
            "95f17570e508ef6a2b2ad1b4f5cade33",
            "fb2883cec1c4fcadd6d1371f6ea491e00000003141042d441ee7f9ff6a0329a64927d0524fdbe7b22c6fb65e10ab4fdc038f94420a0ca3fa28dad36c84ec91a162eae078faad2c1ced78de8113e19602b20e894f4976b973e2fcf682fa0c8ccd9af3d5bff1ede16fad5a31ce19d38b5e1fe1f78a4fad842bbc10254c2c6cdd96a2b55284d972c53cad8c3bacb10f5f57eb0d4a4333b604102ba117cae29108fbd9f629a8ba6960dd01945b39ed37ba706c434a10fd2bd2094ff9249bcdad45135f5fe45fcd38071f8b2d3941afda439810d77aacaf7ce50b54325bf58c9503337d073785a323dfa343"
        ).unwrap();
        assert_eq!(plaintext, "Hello, world");
    }

    #[test]
    fn test_ietf_rfc() {
        let plaintext = try_decrypt(
            "ab5757a70dd4a53e553a6bbf71ffefea2874ec07a6b379e3c48f895a02dc33de",
            "05305932a1c7eabe13b6cec9fda48882",
            "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0ff297de5b429bba7153d3a4ae0caa091fd425f3b4b5414add8ab37a19c1bbb05cf5cb5b2a2e0562d558635641ec52812c6c8ff42e95ccb86be7cd"
        ).unwrap();
        assert_eq!(plaintext, "When I grow up, I want to be a watermelon");
    }

    #[test]
    fn test_rs_18_pad_0() {
        let plaintext = try_decrypt(
            "27433fab8970b3cb5284b61183efb46286562cd2a7330d8cae960911a5571d0c",
            "d65a04df95f2db5e604839f717dcde79",
            "7caebdbc20938ee340a946f1bd4f68f100000012410437cfdb5223d9f95eaa02f6ed940ff22eaf05b3622e949dc3ce9f335e6ef9b26aeaacca0f74080a8b364592f2ccc6d5eddd43004b70b91887d144d9fa93f16c3bc7ea68f4fd547a94eca84b16e138a6080177"
        ).unwrap();
        assert_eq!(plaintext, "1");
    }

    #[test]
    fn test_missing_header_block() {
        let err = try_decrypt(
            "1be83f38332ef09681faf3f307b1ff2e10cab78cc7cdab683ac0ee92ac3f6ee1",
            "3471bb98481e02533bf39542bcf3dba4",
            "45b74d2b69be9b074de3b35aa87e7c15611d",
        )
        .unwrap_err();
        match err.kind() {
            ErrorKind::HeaderTooShort => {}
            _ => assert!(false),
        };
    }

    #[test]
    fn test_truncated_sender_key() {
        let err = try_decrypt(
            "ce88e8e0b3057a4752eb4c8fa931eb621c302da5ad03b81af459cf6735560cae",
            "5c31e0d96d9a139899ac0969d359f740",
            "de5b696b87f1a15cb6adebdd79d6f99e000000120100b6bc1826c37c9f73dd6b4859c2b505181952",
        )
        .unwrap_err();
        match err.kind() {
            ErrorKind::InvalidKeyLength => {}
            _ => assert!(false),
        };
    }

    #[test]
    fn test_truncated_auth_secret() {
        let err = try_decrypt(
            "60c7636a517de7039a0ac2d0e3064400794c78e7e049398129a227cee0f9a801",
            "355a38cd6d9bef15990e2d3308dbd600",
            "8115f4988b8c392a7bacb43c8f1ac5650000001241041994483c541e9bc39a6af03ff713aa7745c284e138a42a2435b797b20c4b698cf5118b4f8555317c190eabebfab749c164d3f6bdebe0d441719131a357d8890a13c4dbd4b16ff3dd5a83f7c91ad6e040ac42730a7f0b3cd3245e9f8d6ff31c751d410cfd"
        ).unwrap_err();
        match err.kind() {
            ErrorKind::CryptoError => {}
            _ => assert!(false),
        };
    }

    #[test]
    fn test_early_final_record() {
        let err = try_decrypt(
            "5dda1d918bc407ba3cda12cb8014d49aa7e0269002820304466bc80034ca9240",
            "40c241fde4269ee1e6d725592d982718",
            "dbe215507d1ad3d2eaeabeae6e874d8f0000001241047bc4343f34a8348cdc4e462ffc7c40aa6a8c61a739c4c41d45125505f70e9fc5f9efa86852dd488dcf8e8ea2cafb75e07abd5ee7c9d5c038bafef079571b0bda294411ce98c76dd031c0e580577a4980a375e45ed30429be0e2ee9da7e6df8696d01b8ec"
        ).unwrap_err();
        match err.kind() {
            ErrorKind::DecryptPadding => {}
            _ => assert!(false),
        };
    }
}
