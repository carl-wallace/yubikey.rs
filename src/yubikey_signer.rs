use crate::certificate::{write, CertInfo, DigestInfo};
use der::asn1::{BitString, ObjectIdentifier, OctetString};
use der::oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, ID_SHA_256, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1,
    SHA_256_WITH_RSA_ENCRYPTION,
};
use der::{Any, Decode, Encode};
use rsa::pkcs1::RsaPublicKey;
use rsa::pkcs8::spki;
use signature::digest::Digest;
use signature::{Keypair, Signer};
use spki::AlgorithmIdentifierOwned;
use spki::Document;
use spki::DynSignatureAlgorithmIdentifier;
use spki::EncodePublicKey;
use spki::SignatureBitStringEncoding;
use spki::SubjectPublicKeyInfoOwned;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use crate::piv::{sign_data, AlgorithmId, SlotId};
use crate::YubiKey;
/// SigningKey implementation for YubiKey
#[derive(Debug)]
pub struct YubiKeySigningKey<'a, D>
where
    D: Digest,
{
    inner: Arc<Mutex<RefCell<&'a mut YubiKey>>>,
    slot: SlotId,
    spki: SubjectPublicKeyInfoOwned, // todo - this should be read from Yubikey, sticking here for the moment owing to workflow
    phantom: PhantomData<D>,
}

impl<'a, D> YubiKeySigningKey<'_, D>
where
    D: Digest,
{
    /// Create new YubiKeySigningKey
    pub fn new(
        key: &'a mut YubiKey,
        slot: SlotId,
        spki: SubjectPublicKeyInfoOwned,
    ) -> YubiKeySigningKey<'_, D> {
        YubiKeySigningKey {
            inner: Arc::new(Mutex::new(RefCell::new(key))),
            slot,
            spki,
            phantom: Default::default(),
        }
    }

    /// Write encoded certificate to associated slot
    pub fn write_cert(&self, encoded_cert: &[u8]) -> crate::Result<()> {
        let yubikey_guard = if let Ok(g) = self.inner.lock() {
            g
        } else {
            return Err(crate::Error::GenericError);
        };
        let mut yubikey = yubikey_guard.deref().borrow_mut();
        write(
            &mut yubikey,
            self.slot,
            CertInfo::Uncompressed,
            encoded_cert,
        )
    }
}

pub struct Signature(Vec<u8>);
impl SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.0.clone())
    }
}

/// VerifyingKey implementation for YubiKey
#[derive(Debug, Clone)]
pub struct YubiKeyVerifyingKey<D>
where
    D: Digest,
{
    pub(super) spki: SubjectPublicKeyInfoOwned,
    pub(super) phantom: PhantomData<D>,
}

impl<D> YubiKeyVerifyingKey<D> where D: Digest + Clone {}

impl<D> EncodePublicKey for YubiKeyVerifyingKey<D>
where
    D: Digest,
{
    /// Return DER encoded SubjectPublicKeyInfo
    fn to_public_key_der(&self) -> Result<Document, spki::Error> {
        match self.spki.to_der() {
            Ok(s) => Ok(Document::try_from(s)?),
            Err(e) => Err(spki::Error::Asn1(e)),
        }
    }
}

impl<D> DynSignatureAlgorithmIdentifier for YubiKeySigningKey<'_, D>
where
    D: Digest + Clone,
{
    fn signature_algorithm_identifier(&self) -> Result<AlgorithmIdentifierOwned, spki::Error> {
        Ok(AlgorithmIdentifierOwned {
            oid: get_sig_alg_from_spki(&self.spki),
            parameters: Some(Any::new(der::Tag::Null, vec![]).unwrap()),
        })
    }
}

fn get_sig_alg_from_spki(spki: &SubjectPublicKeyInfoOwned) -> ObjectIdentifier {
    if ID_EC_PUBLIC_KEY == spki.algorithm.oid {
        ECDSA_WITH_SHA_256
    } else {
        SHA_256_WITH_RSA_ENCRYPTION
    }
}

fn get_em_len(spki: &SubjectPublicKeyInfoOwned) -> crate::Result<usize> {
    let rsa = match RsaPublicKey::from_der(spki.subject_public_key.raw_bytes()) {
        Ok(rsa) => rsa,
        Err(_e) => return Err(crate::Error::AlgorithmError),
    };
    Ok(rsa.modulus.len().try_into().unwrap())
}

fn get_named_curve_parameter(alg_id: &AlgorithmIdentifierOwned) -> crate::Result<ObjectIdentifier> {
    if let Some(params) = &alg_id.parameters {
        if let Ok(oid) = ObjectIdentifier::try_from(params.value()) {
            return Ok(oid);
        }
    }
    Err(crate::Error::GenericError)
}

fn get_alg_id(spki: &SubjectPublicKeyInfoOwned) -> crate::Result<AlgorithmId> {
    if RSA_ENCRYPTION == spki.algorithm.oid {
        let em_len = get_em_len(spki).unwrap();
        let alg = match em_len {
            128 => AlgorithmId::Rsa1024,
            256 => AlgorithmId::Rsa2048,
            _ => panic!(),
        };
        Ok(alg)
    } else if ID_EC_PUBLIC_KEY == spki.algorithm.oid {
        let named_curve = get_named_curve_parameter(&spki.algorithm).unwrap();
        let alg = match named_curve {
            SECP_256_R_1 => AlgorithmId::EccP256,
            SECP_384_R_1 => AlgorithmId::EccP384,
            _ => panic!(),
        };
        Ok(alg)
    } else {
        panic!()
    }
}

impl<D> Signer<Signature> for YubiKeySigningKey<'_, D>
where
    D: Digest,
{
    /// Sign the given message and return a digital signature
    fn sign(&self, msg: &[u8]) -> Signature {
        self.try_sign(msg).expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let oid = get_sig_alg_from_spki(&self.spki.clone());
        if SHA_256_WITH_RSA_ENCRYPTION == oid {
            let d = match OctetString::new(D::digest(msg).to_vec()) {
                Ok(d) => d,
                Err(_e) => return Err(signature::Error::new()),
            };
            let ysd = DigestInfo {
                digest_algorithm: AlgorithmIdentifierOwned {
                    oid: ID_SHA_256,
                    parameters: Some(Any::new(der::Tag::Null, vec![]).unwrap()),
                },
                digest: d,
            };

            let em_len = match get_em_len(&self.spki) {
                Ok(l) => l,
                Err(_) => return Err(signature::Error::new()),
            };

            let alg = get_alg_id(&self.spki).unwrap();

            let mut t = ysd.to_der().unwrap();
            let tlen = t.len();
            let mut em = vec![];
            em.append(&mut vec![0x00_u8, 0x01]);
            em.append(&mut vec![0xff_u8; em_len - tlen - 3]);
            em.append(&mut vec![0x00_u8]);
            em.append(&mut t);
            let yubikey_guard = if let Ok(g) = self.inner.lock() {
                g
            } else {
                return Err(signature::Error::new());
            };
            let mut yubikey = yubikey_guard.deref().borrow_mut();

            let signature_buf = match sign_data(&mut yubikey, em.as_slice(), alg, self.slot) {
                Ok(s) => s,
                Err(e) => {
                    println!("{:?}", e);
                    panic!()
                }
            };
            Ok(Signature(signature_buf.to_vec()))
        } else {
            let alg = get_alg_id(&self.spki).unwrap();
            let yubikey_guard = if let Ok(g) = self.inner.lock() {
                g
            } else {
                return Err(signature::Error::new());
            };
            let mut yubikey = yubikey_guard.deref().borrow_mut();
            let signature_buf = match sign_data(&mut yubikey, &D::digest(msg), alg, self.slot) {
                Ok(s) => s,
                Err(_e) => return Err(signature::Error::new()),
            };
            Ok(Signature(signature_buf.to_vec()))
        }
    }
}

impl<D> Keypair for YubiKeySigningKey<'_, D>
where
    D: Digest + Clone,
{
    type VerifyingKey = YubiKeyVerifyingKey<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        YubiKeyVerifyingKey {
            spki: self.spki.clone(),
            phantom: Default::default(),
        }
    }
}
