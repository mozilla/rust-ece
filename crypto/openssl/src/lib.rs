/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate ece_crypto;
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate sha2;

use ece_crypto::*;

use hkdf::Hkdf;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::Sha256;

lazy_static! {
    static ref GROUP_P256: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
}

fn extract_prv_and_pub_from_raw(raw_ec_prv_key: &[u8]) -> Result<(BigNum, EcPoint), Error> {
    let d = BigNum::from_slice(raw_ec_prv_key)?;
    let bn_ctx = BigNumContext::new()?;
    let mut pub_key_point = EcPoint::new(&GROUP_P256)?;
    pub_key_point.mul_generator(&GROUP_P256, &d, &bn_ctx)?;
    Ok((d, pub_key_point))
}

fn import_raw_ec_prv_key(raw_ec_prv_key: &[u8]) -> Result<EcKey<Private>, Error> {
    let (d, pub_key_point) = extract_prv_and_pub_from_raw(raw_ec_prv_key)?;
    EcKey::from_private_components(&GROUP_P256, &d, &pub_key_point).map_err(|e| e.into())
}

fn import_raw_ec_pub_key(raw_ec_pub_key: &[u8]) -> Result<EcKey<Public>, Error> {
    let mut bn_ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&GROUP_P256, raw_ec_pub_key, &mut bn_ctx)?;
    EcKey::from_public_key(&GROUP_P256, &point).map_err(|e| e.into())
}

pub struct KeysImpl {
    raw_local_ec_prv_key: Vec<u8>,
    raw_remote_ec_pub_key: Vec<u8>,
}

impl KeysImpl {
    fn with_ephemeral_local_keypair(raw_remote_ec_pub_key: &[u8]) -> Result<Self, Error> {
        let raw_local_ec_prv_key = vec![0u8; 0]; // TODO
        Ok(Self::with_keys(raw_remote_ec_pub_key, &raw_local_ec_prv_key))
    }

    fn with_keys(raw_remote_ec_pub_key: &[u8], raw_local_ec_prv_key: &[u8]) -> Self {
        Self {
            raw_local_ec_prv_key: raw_local_ec_prv_key.to_vec(),
            raw_remote_ec_pub_key: raw_remote_ec_pub_key.to_vec(),
        }
    }
}

impl Keys for KeysImpl {
    fn compute_ecdh_secret(
        &self,
    ) -> Result<Vec<u8>, Error> {
        let private = import_raw_ec_prv_key(&self.raw_local_ec_prv_key)?;
        let private = PKey::from_ec_key(private)?;
        let public = import_raw_ec_pub_key(&self.raw_remote_ec_pub_key)?;
        let public = PKey::from_ec_key(public)?;
        let mut deriver = Deriver::new(&private)?;
        deriver.set_peer(&public)?;
        let shared_key = deriver.derive_to_vec()?;
        Ok(shared_key)
    }

    fn raw_local_pub_key(&self) -> Result<Vec<u8>, Error> {
        let (_, pub_key_point) = extract_prv_and_pub_from_raw(&self.raw_local_ec_prv_key)?;
        let mut bn_ctx = BigNumContext::new()?;
        let uncompressed =
            pub_key_point.to_bytes(&GROUP_P256, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)?;
        Ok(uncompressed)
    }

    fn raw_remote_pub_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.raw_remote_ec_pub_key.clone())
    }
}

pub struct CryptoImpl;
impl<'a> Crypto<'a> for CryptoImpl {
    type PrivateKey = &'a [u8];
    type PublicKey = &'a [u8];
    type Keys = KeysImpl;

    fn keys_with_ephemeral_local_keypair(remote_pub_key: Self::PublicKey) -> Result<Self::Keys, Error> {
        KeysImpl::with_ephemeral_local_keypair(remote_pub_key)
    }

    fn keys_with_existing_local_keypair(remote_pub_key: Self::PublicKey, local_prv_key: Self::PrivateKey) -> Result<Self::Keys, Error> {
        Ok(KeysImpl::with_keys(remote_pub_key, local_prv_key))
    }

    fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        let hk = Hkdf::<Sha256>::extract(Some(&salt[..]), &secret);
        let mut okm = vec![0u8; len];
        hk.expand(&info, &mut okm).unwrap();
        Ok(okm)
    }

    fn aes_gcm_128_decrypt(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::aes_128_gcm();
        let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
        let mut out = vec![0; data.len() + cipher.block_size()];
        let count = c.update(data, &mut out)?;
        c.set_tag(tag)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }
}
