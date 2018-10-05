/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate failure;

pub type Error = failure::Error;

pub trait Crypto {
    fn compute_ecdh_secret(
        raw_local_ec_prv_key: &[u8],
        raw_remote_ec_pub_key: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn ec_prv_uncompressed_point(raw_key: &[u8]) -> Result<Vec<u8>, Error>;
    fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error>;
    fn aes_gcm_128_decrypt(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error>;
}
