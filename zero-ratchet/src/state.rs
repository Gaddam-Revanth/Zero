//! ZR Double Ratchet state machine.

use crate::{
    error::RatchetError,
    header::{decrypt_header, encrypt_header, DecryptedHeader, EncryptedHeader},
    skipped_keys::SkippedKeyCache,
};
use serde::{Deserialize, Serialize};
use zero_crypto::{
    aead::{decrypt, encrypt, AeadKey, AeadNonce},
    dh::{x25519_diffie_hellman, X25519Keypair, X25519PublicKey, X25519SecretKey},
    kdf::{hkdf_expand, hkdf_extract, KdfContext},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum messages to skip before treating as attack.
const MAX_SKIP: usize = 1000;

/// Initialization parameters for a new ZR session.
#[derive(Clone)]
pub struct SessionInit {
    /// The master secret from ZKX (64 bytes).
    pub master_secret: Vec<u8>,
    /// Whether this side is the initiator (Alice) or responder (Bob).
    pub is_initiator: bool,
    /// Local DH ratchet keypair to start the session with.
    /// This MUST be freshly generated per session.
    pub local_dh: X25519Keypair,
    /// Remote party's initial ratchet public key (exchanged at session start).
    pub remote_dh_pub: X25519PublicKey,
}

/// A ZR ratchet session — maintains all state for one conversation.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
    #[zeroize(skip)]
    dhs_pub: X25519PublicKey,
    /// Remote party's DH ratchet public key.
    #[zeroize(skip)]
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
    #[zeroize(skip)]
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
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl RatchetSession {
    /// Return our current DH ratchet public key.
    pub fn dh_pub(&self) -> X25519PublicKey {
        self.dhs_pub.clone()
    }

    /// Create a new ZR session.
    pub fn new(init: SessionInit) -> Result<Self, RatchetError> {
        if init.master_secret.len() != 64 {
            return Err(RatchetError::SerializationError(format!(
                "Invalid master_secret length: expected 64, got {}",
                init.master_secret.len()
            )));
        }

        let dhs_secret = init.local_dh.secret_key();
        let dhs_pub = init.local_dh.public_key();

        // Initial shared secret using the initial ratchet DH keys.
        // This is required to seed sending/receiving chains deterministically for both sides.
        let shared0 = x25519_diffie_hellman(&dhs_secret, &init.remote_dh_pub)
            .map_err(|_| RatchetError::DhFailed)?;

        // Root key starts as master_secret; then we mix in the initial DH to derive chain keys.
        let (rk1, ck0) = kdf_rk(&init.master_secret, &shared0.0)?;

        // Derive header keys from the root key. Role separation ensures Alice's send header key
        // matches Bob's receive header key (and vice versa).
        let prk_hdr = hkdf_extract(&rk1, b"ZERO-ZR-v1-header");
        let hk_send = hkdf_expand(&prk_hdr, KdfContext::ZrHeaderKeySend, 32)
            .map_err(|_| RatchetError::KdfError)?;
        let hk_recv = hkdf_expand(&prk_hdr, KdfContext::ZrHeaderKeyRecv, 32)
            .map_err(|_| RatchetError::KdfError)?;

        // Role separation:
        // - Initiator: cks=ck_send, ckr=ck_recv, hks=hk_send, hkr=hk_recv
        // - Responder: cks=ck_recv, ckr=ck_send, hks=hk_recv, hkr=hk_send
        let (ck_send, ck_recv) = ck0;
        let (cks, ckr, hks, hkr) = if init.is_initiator {
            (Some(ck_send), Some(ck_recv), hk_send, hk_recv)
        } else {
            (Some(ck_recv), Some(ck_send), hk_recv, hk_send)
        };

        let mut session = Self {
            rk: rk1,
            cks,
            ckr,
            dhs_secret,
            dhs_pub,
            dhr: Some(init.remote_dh_pub),
            ns: 0,
            nr: 0,
            pn: 0,
            hks,
            hkr,
            // Next header keys start as current header keys (updated on DH ratchet step).
            nhks: vec![0u8; 32],
            nhkr: vec![0u8; 32],
            skipped: SkippedKeyCache::new(),
        };

        // Initialize "next header keys" to a derived value so the receiver can attempt both
        // current and next during a ratchet transition.
        let prk_nh = hkdf_extract(&session.rk, b"ZERO-ZR-v1-next-header");
        session.nhks = hkdf_expand(&prk_nh, KdfContext::Custom("ZERO-ZR-v1-nhks"), 32)
            .map_err(|_| RatchetError::KdfError)?;
        session.nhkr = hkdf_expand(&prk_nh, KdfContext::Custom("ZERO-ZR-v1-nhkr"), 32)
            .map_err(|_| RatchetError::KdfError)?;

        Ok(session)
    }

    /// R6: Perform a PQ ratchet step by mixing in a post-quantum shared secret.
    /// This provides ongoing post-quantum forward secrecy.
    pub fn pq_ratchet_step(&mut self, kem_shared_secret: &[u8; 32]) -> Result<(), RatchetError> {
        let prk = hkdf_extract(&self.rk, kem_shared_secret);
        self.rk =
            hkdf_expand(&prk, KdfContext::ZrRootChain, 64).map_err(|_| RatchetError::KdfError)?;
        Ok(())
    }

    fn dh_ratchet_step(&mut self, remote_pub: &X25519PublicKey) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(remote_pub.clone());

        let shared = x25519_diffie_hellman(&self.dhs_secret, remote_pub)
            .map_err(|_| RatchetError::DhFailed)?;

        let (new_rk, ck_pair) = kdf_rk(&self.rk, &shared.0)?;
        self.rk = new_rk;
        // After a DH ratchet step, we create a new sending chain.
        // (Receiving chain will be derived when processing messages from the remote side.)
        self.cks = Some(ck_pair.0);

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
        self.nhks = hkdf_expand(&prk, KdfContext::Custom("ZERO-ZR-v1-nhks"), 32)
            .map_err(|_| RatchetError::KdfError)?;
        self.nhkr = hkdf_expand(&prk, KdfContext::Custom("ZERO-ZR-v1-nhkr"), 32)
            .map_err(|_| RatchetError::KdfError)?;

        Ok(())
    }

    /// Encrypt a message using the current sending chain.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, RatchetError> {
        let (new_cks, mk) = kdf_ck(self.cks.as_ref().ok_or(RatchetError::EncryptionFailed)?)?;
        self.cks = Some(new_cks);

        let hdr = DecryptedHeader {
            dh_pub: self.dhs_pub.clone(),
            prev_counter: self.pn,
            counter: self.ns,
        };
        self.ns += 1;

        let hks_arr: [u8; 32] = self
            .hks
            .as_slice()
            .try_into()
            .map_err(|_| RatchetError::KdfError)?;
        let enc_hdr = encrypt_header(&AeadKey(hks_arr), &hdr)?;

        let mut aad = associated_data.to_vec();
        aad.extend_from_slice(&enc_hdr.0);

        let nonce = AeadNonce::random();
        let mut ct_with_nonce = nonce.0.to_vec();

        let mk_arr: [u8; 32] = mk
            .as_slice()
            .try_into()
            .map_err(|_| RatchetError::KdfError)?;
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
        let hkr_arr: [u8; 32] = self
            .hkr
            .as_slice()
            .try_into()
            .map_err(|_| RatchetError::KdfError)?;
        if let Ok(hdr) = decrypt_header(&AeadKey(hkr_arr), &msg.header) {
            if let Some(mk) = self.skipped.take(&hdr.dh_pub, hdr.counter) {
                return self.decrypt_with_key(&mk, msg, associated_data);
            }
            self.skip_message_keys(hdr.counter, &hdr.dh_pub, now_secs)?;
            let (new_ckr, mk) = kdf_ck(self.ckr.as_ref().ok_or(RatchetError::DecryptionFailed)?)?;
            self.ckr = Some(new_ckr);
            self.nr += 1;
            let mk_arr: [u8; 32] = mk
                .as_slice()
                .try_into()
                .map_err(|_| RatchetError::KdfError)?;
            return self.decrypt_with_key(&mk_arr, msg, associated_data);
        }

        let nhkr_arr: [u8; 32] = self
            .nhkr
            .as_slice()
            .try_into()
            .map_err(|_| RatchetError::KdfError)?;
        if let Ok(hdr) = decrypt_header(&AeadKey(nhkr_arr), &msg.header) {
            if let Some(ref _ckr) = self.ckr {
                let dhr = self.dhr.clone().ok_or(RatchetError::DecryptionFailed)?;
                self.skip_message_keys(hdr.prev_counter, &dhr, now_secs)?;
            }
            self.dh_ratchet_step(&hdr.dh_pub)?;
            self.skip_message_keys(hdr.counter, &hdr.dh_pub, now_secs)?;
            let (new_ckr, mk) = kdf_ck(self.ckr.as_ref().ok_or(RatchetError::DecryptionFailed)?)?;
            self.ckr = Some(new_ckr);
            self.nr += 1;
            let mk_arr: [u8; 32] = mk
                .as_slice()
                .try_into()
                .map_err(|_| RatchetError::KdfError)?;
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
        if ct.len() < 12 {
            return Err(RatchetError::DecryptionFailed);
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ct[..12]);
        let nonce = AeadNonce(nonce_bytes);
        let mut aad = associated_data.to_vec();
        aad.extend_from_slice(&msg.header.0);
        decrypt(&AeadKey(*mk), &nonce, &ct[12..], &aad).map_err(|_| RatchetError::DecryptionFailed)
    }

    fn skip_message_keys(
        &mut self,
        until: u32,
        dh_pub: &X25519PublicKey,
        now: u64,
    ) -> Result<(), RatchetError> {
        if self.nr + (MAX_SKIP as u32) < until {
            return Err(RatchetError::TooManySkippedKeys {
                skipped: (until - self.nr) as usize,
                max: MAX_SKIP,
            });
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

type KdfRkResult = (Vec<u8>, (Vec<u8>, Vec<u8>));

fn kdf_rk(rk: &[u8], dh_shared: &[u8]) -> Result<KdfRkResult, RatchetError> {
    let prk = hkdf_extract(rk, dh_shared);
    let rk = hkdf_expand(&prk, KdfContext::ZrRootChain, 64).map_err(|_| RatchetError::KdfError)?;
    let ck_send =
        hkdf_expand(&prk, KdfContext::ZrSendChain, 32).map_err(|_| RatchetError::KdfError)?;
    let ck_recv =
        hkdf_expand(&prk, KdfContext::ZrRecvChain, 32).map_err(|_| RatchetError::KdfError)?;
    Ok((rk, (ck_send, ck_recv)))
}

fn kdf_ck(ck: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    let prk = hkdf_extract(ck, &[]);
    let nck = hkdf_expand(&prk, KdfContext::ZrSendChain, 32).map_err(|_| RatchetError::KdfError)?;
    let mk = hkdf_expand(&prk, KdfContext::ZrMessageKey, 32).map_err(|_| RatchetError::KdfError)?;
    Ok((nck, mk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zr_encrypt_decrypt_roundtrip() {
        // Simulate two parties establishing a session from the same ZKX master secret.
        let master = vec![0x11u8; 64];
        let master_for_bob = master.clone();

        let alice_kp = X25519Keypair::generate();
        let bob_kp = X25519Keypair::generate();

        let mut alice = RatchetSession::new(SessionInit {
            master_secret: master.clone(),
            is_initiator: true,
            local_dh: alice_kp,
            remote_dh_pub: bob_kp.public_key(),
        })
        .expect("alice init");

        let mut bob = RatchetSession::new(SessionInit {
            master_secret: master_for_bob.clone(),
            is_initiator: false,
            local_dh: bob_kp,
            remote_dh_pub: alice.dhs_pub.clone(),
        })
        .expect("bob init");

        // Use consistent associated data (e.g., canonical header bytes in real protocol)
        let ad = b"ad";
        let msg = alice.encrypt(b"hello", ad).expect("encrypt");

        // Bob must be able to decrypt it
        let pt = bob.decrypt(&msg, ad, 0).expect("decrypt");
        assert_eq!(pt, b"hello");
    }
}
