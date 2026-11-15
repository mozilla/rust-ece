/* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#![cfg(feature = "backend-openssl")]

use ece::{legacy, EcKeyComponents, Error};

#[test]
fn decrypt_returns_key_import_errors() {
    let (key, auth) = ece::generate_keypair_and_auth_secret().unwrap();
    let components = key.raw_components().unwrap();
    let ciphertext = ece::encrypt(components.public_key(), &auth, b"message").unwrap();
    assert_eq!(
        ece::decrypt(&components, &auth, &ciphertext).unwrap(),
        b"message"
    );

    for public_key in [Vec::new(), vec![4], vec![255; 65]] {
        let invalid = EcKeyComponents::new(components.private_key().to_vec(), public_key);
        assert!(matches!(
            ece::decrypt(&invalid, &auth, &ciphertext),
            Err(Error::OpenSSLError(_))
        ));
    }
}

#[test]
fn legacy_decrypt_returns_key_import_errors() {
    let (key, auth) = ece::generate_keypair_and_auth_secret().unwrap();
    let components = key.raw_components().unwrap();
    let ciphertext = legacy::encrypt_aesgcm(components.public_key(), &auth, b"message").unwrap();
    assert_eq!(
        legacy::decrypt_aesgcm(&components, &auth, &ciphertext).unwrap(),
        b"message"
    );

    for public_key in [Vec::new(), vec![4], vec![255; 65]] {
        let invalid = EcKeyComponents::new(components.private_key().to_vec(), public_key);
        assert!(matches!(
            legacy::decrypt_aesgcm(&invalid, &auth, &ciphertext),
            Err(Error::OpenSSLError(_))
        ));
    }
}
