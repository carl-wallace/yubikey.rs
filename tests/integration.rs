//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use log::trace;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
//use rsa::{hash::Hash::SHA2_256, PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::{env, sync::Mutex};
use yubikey::{
    piv::{self, AlgorithmId, Key, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use der::Encode;
use p256::ecdsa::signature::Verifier as Verifier256;
use p256::ecdsa::Signature as Signature256;
use p256::ecdsa::VerifyingKey as VerifyingKey256;
use p256::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use x509_cert::Certificate;
use yubikey::certificate::generate_self_signed;
use yubikey::YubiKeySigningKey;

static YUBIKEY: Lazy<Mutex<YubiKey>> = Lazy::new(|| {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };

    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
});

//
// CCCID support
//

#[test]
#[ignore]
fn test_get_cccid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.cccid() {
        Ok(cccid) => trace!("CCCID: {:?}", cccid),
        Err(Error::NotFound) => trace!("CCCID not found"),
        Err(err) => panic!("error getting CCCID: {:?}", err),
    }
}

//
// CHUID support
//

#[test]
#[ignore]
fn test_get_chuid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.chuid() {
        Ok(chuid) => trace!("CHUID: {:?}", chuid),
        Err(Error::NotFound) => trace!("CHUID not found"),
        Err(err) => panic!("error getting CHUID: {:?}", err),
    }
}

//
// Device config support
//

#[test]
#[ignore]
fn test_get_config() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let config_result = yubikey.config();
    assert!(config_result.is_ok());
    trace!("config: {:?}", config_result.unwrap());
}

//
// Cryptographic key support
//

#[test]
fn test_list_keys() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let keys_result = Key::list(&mut yubikey);
    assert!(keys_result.is_ok());
    trace!("keys: {:?}", keys_result.unwrap());
}

//
// PIN support
//

#[test]
#[ignore]
fn test_verify_pin() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"000000").is_err());
    assert!(yubikey.verify_pin(b"123456").is_ok());
}

//
// Management key support
//

#[cfg(feature = "untested")]
#[test]
#[ignore]
fn test_set_mgmkey() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate().set_protected(&mut yubikey).is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_ok());

    // Set a manual management key.
    let manual = MgmKey::generate();
    assert!(manual.set_manual(&mut yubikey, false).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_err());
    assert!(yubikey.authenticate(manual.clone()).is_ok());

    // Set back to the default management key.
    assert!(MgmKey::set_default(&mut yubikey).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(protected).is_err());
    assert!(yubikey.authenticate(manual).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());
}

//
// Certificate support
//

fn generate_self_signed_cert(algorithm: AlgorithmId) -> Certificate {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        algorithm,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let signer: YubiKeySigningKey<'_, Sha256> =
        YubiKeySigningKey::new(&mut yubikey, SlotId::Retired(RetiredSlotId::R1), generated);

    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] = 0x01;

    // Generate a self-signed certificate for the new key.
    let cert_result = generate_self_signed(signer, &serial, None, "cn=testSubject");

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
fn generate_self_signed_rsa_cert2048() {
    let cert = generate_self_signed_cert(AlgorithmId::Rsa2048);
    let tbsbuf = cert.tbs_certificate.to_der().unwrap();
    let hash_to_verify = Sha256::digest(tbsbuf.as_slice()).to_vec();
    let spkibuf = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let rsa = RsaPublicKey::from_public_key_der(&spkibuf).unwrap();
    let ps = Pkcs1v15Sign::new::<Sha256>();
    let x = rsa.verify(
        ps,
        hash_to_verify.as_slice(),
        cert.signature.as_bytes().unwrap(),
    );
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}

#[test]
fn generate_self_signed_rsa_cert1024() {
    let cert = generate_self_signed_cert(AlgorithmId::Rsa1024);
    let tbsbuf = cert.tbs_certificate.to_der().unwrap();
    let hash_to_verify = Sha256::digest(tbsbuf.as_slice()).to_vec();
    let spkibuf = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let rsa = RsaPublicKey::from_public_key_der(&spkibuf).unwrap();
    let ps = Pkcs1v15Sign::new::<Sha256>();
    let x = rsa.verify(
        ps,
        hash_to_verify.as_slice(),
        cert.signature.as_bytes().unwrap(),
    );
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}

#[test]
fn generate_self_signed_ec_cert() {
    let cert = generate_self_signed_cert(AlgorithmId::EccP256);
    let tbsbuf = cert.tbs_certificate.to_der().unwrap();
    let ecdsa = VerifyingKey256::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap(),
    )
    .unwrap();
    let s = Signature256::from_der(cert.signature.as_bytes().unwrap()).unwrap();
    let x = ecdsa.verify(tbsbuf.as_slice(), &s);
    if let Err(e) = x {
        panic!(
            "Self-signed certificate signature failed to verify: {:?}",
            e
        );
    }
}
