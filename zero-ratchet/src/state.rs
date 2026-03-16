//! ZR Double Ratchet state machine.

use crate::{
    error::RatchetError,
    header::{decrypt_header, encrypt_header, DecryptedHeader, EncryptedHeader},
    skipped_keys::SkippedKeyCache,
};
use serde::{Deserialize, Serialize};
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::{X25519Keypair, X25519PublicKey, X25519SecretKey, x25519_diffie_hellman},
    kdf::{hkdf_extract, hkdf_expand, KdfContext},
};

/// Maximum messages to skip before treating as attack.
const MAX_SKIP: usize = 1000;

/// Initialization parameters for a new ZR session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInit {
    /// The master secret from ZKX (64 bytes).
    pub master_secret: Vec<u8>,
    /// Whether this side is the initiator (Alice) or responder (Bob).
    pub is_initiator: bool,
    /// Bob's initial ratchet public key (from the ZKX message).
    pub remote_dh_pub: Option<X25519PublicKey>,
}

/// A ZR ratchet session — maintains all state for one conversation.
#[derive(Serialize, Deserialize)]
pub struct RatchetSession {
    /// Root key (64 bytes).
    rk: Vec<u8>,
    /// Sending chain key (32 bytes).
    cks: Option<Vec<u8>>,
    /// Receiving chain key (32 bytes).
    ckr: Option<Vec<u8>>,
    /// Our current DH ratchet secret key.
    dhs_secret: X25519SecretKey,
    /// Our current DH ratchet public key.
    dhs_pub: X25519PublicKey,
    /// Remote party's DH ratchet public key.
    dhr: Option<X25519PublicKey>,
    /// Messages sent in current sending chain.
    ns: u32,
    /// Messages received in current receiving chain.
    nr: u32,
    /// Messages sent in previous sending chain.
    pn: u32,
    /// Header key for sending (HKs).
    hks: Vec<u8>,
    /// Header key for receiving (HKr).
    hkr: Vec<u8>,
    /// Next header key for sending.
    nhks: Vec<u8>,
    /// Next header key for receiving.
    nhkr: Vec<u8>,
    /// Skipped key cache.
    #[serde(skip)]
    skipped: SkippedKeyCache,
}

impl std::fmt::Debug for RatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSession")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .finish_non_exhaustive()
    }
}

/// An encrypted ZR message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Encrypted header containing the ratchet PK and counter.
    pub header: EncryptedHeader,
    /// The encrypted message ciphertext.
    pub ciphertext: Vec<u8>,
}

impl RatchetSession {
    /// Create a new ZR session.
    pub fn new(init: SessionInit) -> Result<Self, RatchetError> {
        let kp = X25519Keypair::generate();
        let dhs_secret = kp.secret_key();
        let dhs_pub = kp.public_key();

        let mut session = Self {
            rk: init.master_secret,
            cks: None,
            ckr: None,
            dhs_secret,
            dhs_pub,
            dhr: init.remote_dh_pub.clone(),
            ns: 0,
            nr: 0,
            pn: 0,
            hks: vec![0u8; 32],
            hkr: vec![0u8; 32],
            nhks: vec![0u8; 32],
            nhkr: vec![0u8; 32],
            skipped: SkippedKeyCache::new(),
        };

        if init.is_initiator {
            if let Some(dhr) = init.remote_dh_pub {
                session.dh_ratchet_step(&dhr)?;
            }
        }
        Ok(session)
    }

    fn dh_ratchet_step(&mut self, remote_pub: &X25519PublicKey) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(remote_pub.clone());
        
        let shared = x25519_diffie_hellman(&self.dhs_secret, remote_pub)
            .map_err(|_| RatchetError::DhFailed)?;
            
        let (new_rk, new_cks) = kdf_rk(&self.rk, &shared.0)?;
        self.rk = new_rk;
        self.cks = Some(new_cks);
        
        // Generate new local DH key
        let kp = X25519Keypair::generate();
        self.dhs_secret = kp.secret_key();
        self.dhs_pub = kp.public_key();
        
        // Update header keys
        self.hks = self.nhks.clone();
        self.hkr = self.nhkr.clone();
        
        let nh_shared = x25519_diffie_hellman(&self.dhs_secret, remote_pub)
            .map_err(|_| RatchetError::DhFailed)?;
        let prk = hkdf_extract(&self.rk, &nh_shared.0);
        self.nhks = hkdf_expand(&prk, KdfContext::Custom("ZR-nhks"), 32).map_err(|_| RatchetError::KdfError)?;
        self.nhkr = hkdf_expand(&prk, KdfContext::Custom("ZR-nhkr"), 32).map_err(|_| RatchetError::KdfError)?;
        
        Ok(())
    }

    /// Encrypt a message using the current sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<RatchetMessage, RatchetError> {
        let (new_cks, mk) = kdf_ck(self.cks.as_ref().ok_or(RatchetError::EncryptionFailed)?)?;
        self.cks = Some(new_cks);
        
        let hdr = DecryptedHeader {
            dh_pub: self.dhs_pub.clone(),
            prev_counter: self.pn,
            counter: self.ns,
        };
        self.ns += 1;
        
        let hks_arr: [u8; 32] = self.hks.as_slice().try_into().unwrap_or([0u8; 32]);
        let enc_hdr = encrypt_header(&AeadKey(hks_arr), &hdr)?;
        
        let mut aad = associated_data.to_vec();
        aad.extend_from_slice(&enc_hdr.0);
        
        let nonce = AeadNonce::random();
        let mut ct_with_nonce = nonce.0.to_vec();
        
        let mk_arr: [u8; 32] = mk.as_slice().try_into().unwrap();
        let ct = encrypt(&AeadKey(mk_arr), &nonce, plaintext, &aad)
            .map_err(|_| RatchetError::EncryptionFailed)?;
        ct_with_nonce.extend_from_slice(&ct);

        Ok(RatchetMessage {
            header: enc_hdr,
            ciphertext: ct_with_nonce,
        })
    }

    /// Decrypt an incoming message, handling out-of-order delivery.
    pub fn decrypt(
        &mut self,
        msg: &RatchetMessage,
        associated_data: &[u8],
        now_secs: u64,
    ) -> Result<Vec<u8>, RatchetError> {
        let hkr_arr: [u8; 32] = self.hkr.as_slice().try_into().unwrap_or([0u8; 32]);
        if let Ok(hdr) = decrypt_header(&AeadKey(hkr_arr), &msg.header) {
            if let Some(mk) = self.skipped.take(&hdr.dh_pub, hdr.counter) {
                return self.decrypt_with_key(&mk, msg, associated_data);
            }
            self.skip_message_keys(hdr.counter, &hdr.dh_pub, now_secs)?;
            let (new_ckr, mk) = kdf_ck(self.ckr.as_ref().ok_or(RatchetError::DecryptionFailed)?)?;
            self.ckr = Some(new_ckr);
            self.nr += 1;
            let mk_arr: [u8; 32] = mk.as_slice().try_into().unwrap();
            return self.decrypt_with_key(&mk_arr, msg, associated_data);
        }

        let nhkr_arr: [u8; 32] = self.nhkr.as_slice().try_into().unwrap_or([0u8; 32]);
        if let Ok(hdr) = decrypt_header(&AeadKey(nhkr_arr), &msg.header) {
            if let Some(ref _ckr) = self.ckr {
                self.skip_message_keys(hdr.prev_counter, &self.dhr.clone().unwrap_or(X25519PublicKey([0u8;32])), now_secs)?;
            }
            self.dh_ratchet_step(&hdr.dh_pub)?;
            self.skip_message_keys(hdr.counter, &hdr.dh_pub, now_secs)?;
            let (new_ckr, mk) = kdf_ck(self.ckr.as_ref().ok_or(RatchetError::DecryptionFailed)?)?;
            self.ckr = Some(new_ckr);
            self.nr += 1;
            let mk_arr: [u8; 32] = mk.as_slice().try_into().unwrap();
            return self.decrypt_with_key(&mk_arr, msg, associated_data);
        }

        Err(RatchetError::DecryptionFailed)
    }

    fn decrypt_with_key(
        &self,
        mk: &[u8; 32],
        msg: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let ct = &msg.ciphertext;
        if ct.len() < 12 { return Err(RatchetError::DecryptionFailed); }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ct[..12]);
        let nonce = AeadNonce(nonce_bytes);
        let mut aad = associated_data.to_vec();
        aad.extend_from_slice(&msg.header.0);
        decrypt(&AeadKey(*mk), &nonce, &ct[12..], &aad)
            .map_err(|_| RatchetError::DecryptionFailed)
    }

    fn skip_message_keys(&mut self, until: u32, dh_pub: &X25519PublicKey, now: u64) -> Result<(), RatchetError> {
        if self.nr + (MAX_SKIP as u32) < until {
            return Err(RatchetError::TooManySkippedKeys { skipped: (until - self.nr) as usize, max: MAX_SKIP });
        }
        if let Some(ref mut ckr) = self.ckr {
            while self.nr < until {
                let (new_ckr, mk) = kdf_ck(ckr)?;
                let mut mk_arr = [0u8; 32];
                mk_arr.copy_from_slice(&mk);
                self.skipped.insert(dh_pub.clone(), self.nr, mk_arr, now);
                *ckr = new_ckr;
                self.nr += 1;
            }
        }
        Ok(())
    }
}

fn kdf_rk(rk: &[u8], dh_shared: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    let prk = hkdf_extract(rk, dh_shared);
    let rk = hkdf_expand(&prk, KdfContext::Custom("ZR-rk"), 64).map_err(|_| RatchetError::KdfError)?;
    let ck = hkdf_expand(&prk, KdfContext::Custom("ZR-ck"), 32).map_err(|_| RatchetError::KdfError)?;
    Ok((rk, ck))
}

fn kdf_ck(ck: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    let prk = hkdf_extract(ck, &[]);
    let nck = hkdf_expand(&prk, KdfContext::Custom("ZR-nck"), 32).map_err(|_| RatchetError::KdfError)?;
    let mk = hkdf_expand(&prk, KdfContext::Custom("ZR-mk"), 32).map_err(|_| RatchetError::KdfError)?;
    Ok((nck, mk))
}
