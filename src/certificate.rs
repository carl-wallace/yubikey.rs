//! X.509 certificate support.

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    consts::CB_OBJ_MAX,
    error::{Error, Result},
    piv::SlotId,
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use rsa::pkcs1::der;
use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

use crate::yubikey_signer::YubiKeySigningKey;
use der::{
    asn1::{OctetString, UtcTime},
    Decode, Encode, Sequence,
};
use signature::{digest::Digest, Keypair};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
    Certificate,
};

const TAG_CERT: u8 = 0x70;
const TAG_CERT_COMPRESS: u8 = 0x71;
const TAG_CERT_LRC: u8 = 0xFE;

/// Information about how a [`Certificate`] is stored within a YubiKey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertInfo {
    /// The certificate is uncompressed.
    Uncompressed,

    /// The certificate is gzip-compressed.
    Gzip,
}

impl TryFrom<u8> for CertInfo {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(CertInfo::Uncompressed),
            0x01 => Ok(CertInfo::Gzip),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<CertInfo> for u8 {
    fn from(certinfo: CertInfo) -> u8 {
        match certinfo {
            CertInfo::Uncompressed => 0x00,
            CertInfo::Gzip => 0x01,
        }
    }
}

/// from RFC8017
///    DigestInfo ::= SEQUENCE {
///      digestAlgorithm DigestAlgorithmIdentifier,
///      digest Digest }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    /// algorithm ID for the hash function
    pub digest_algorithm: AlgorithmIdentifierOwned,
    /// hash value
    pub digest: OctetString,
}

/// Creates a new self-signed certificate for the given key. Writes the resulting
/// certificate to the slot before returning it.
///
/// `extensions` is optional; if empty, no extensions will be included.
#[allow(clippy::too_many_arguments)]
pub fn generate_self_signed<'a, D>(
    signer: YubiKeySigningKey<'a, D>,
    serial: &[u8],
    opt_not_after: Option<Time>,
    subject: &str,
) -> Result<Certificate>
where
    D: Digest,
    YubiKeySigningKey<'a, D>: Keypair,
    YubiKeySigningKey<'a, D>: DynSignatureAlgorithmIdentifier,
    <YubiKeySigningKey<'a, D> as Keypair>::VerifyingKey: EncodePublicKey,
{
    let vk = signer.verifying_key();
    let serial_number = SerialNumber::new(serial).unwrap();
    let ten_years_duration = Duration::from_secs(365 * 24 * 60 * 60 * 10);
    let ten_years_time = SystemTime::now().checked_add(ten_years_duration).unwrap();
    let not_after = match opt_not_after {
        Some(na) => na,
        None => Time::UtcTime(
            UtcTime::from_unix_duration(ten_years_time.duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
    };

    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(SystemTime::now().duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
        not_after,
    };
    let profile = Profile::Root;
    let subject = Name::from_str(subject).unwrap().to_der().unwrap();
    let subject = Name::from_der(&subject).unwrap();

    let spkibuf = vk.to_public_key_der().unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_der(spkibuf.as_bytes()).unwrap();

    let builder = CertificateBuilder::new(profile, serial_number, validity, subject, spki, &signer)
        .expect("Create certificate");

    match builder.build() {
        Ok(c) => Ok(c),
        Err(_e) => Err(Error::InvalidObject),
    }
}

/// Read a certificate from the given slot in the YubiKey
pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;
    let buf = read_certificate(&txn, slot)?;

    if buf.is_empty() {
        return Err(Error::InvalidObject);
    }

    Ok(buf)
}

/// Write this certificate into the YubiKey in the given slot
pub fn write(yubikey: &mut YubiKey, slot: SlotId, certinfo: CertInfo, cert: &[u8]) -> Result<()> {
    let txn = yubikey.begin_transaction()?;
    write_certificate(&txn, slot, Some(cert), certinfo)
}

/// Delete a certificate located at the given slot of the given YubiKey
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<()> {
    let txn = yubikey.begin_transaction()?;
    write_certificate(&txn, slot, None, CertInfo::Uncompressed)
}

/// Read certificate
pub(crate) fn read_certificate(txn: &Transaction<'_>, slot: SlotId) -> Result<Buffer> {
    let object_id = slot.object_id();

    let buf = match txn.fetch_object(object_id) {
        Ok(b) => b,
        Err(_) => {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }
    };

    // TODO(str4d): Check the rest of the buffer (TAG_CERT_COMPRESS and TAG_CERT_LRC)
    if buf[0] == TAG_CERT {
        Tlv::parse_single(buf, TAG_CERT).or_else(|_| {
            // TODO(tarcieri): is this really ok?
            Ok(Zeroizing::new(vec![]))
        })
    } else {
        Ok(buf)
    }
}

/// Write certificate
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: CertInfo,
) -> Result<()> {
    let object_id = slot.object_id();

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = Tlv::write(&mut buf, TAG_CERT, data)?;

    // write compression info and LRC trailer
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_COMPRESS, &[certinfo.into()])?;
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_LRC, &[])?;

    txn.save_object(object_id, &buf[..offset])
}
