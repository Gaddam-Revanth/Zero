use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::mpsc;
use zero_crypto::dh::X25519Keypair;

/// A background pool for pre-generating X25519 keypairs.
/// This removes the ~0.7-1ms cost of key generation from the active handshake path.
pub struct EphemeralKeyPool {
    receiver: Mutex<mpsc::Receiver<X25519Keypair>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl EphemeralKeyPool {
    /// Create a new pool with the given capacity.
    pub fn new(capacity: usize) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(capacity);

        // Spawn background task to keep the pool full
        let handle = tokio::spawn(async move {
            loop {
                let kp = X25519Keypair::generate();
                if sender.send(kp).await.is_err() {
                    break; // Channel closed
                }
            }
        });

        Arc::new(Self {
            receiver: Mutex::new(receiver),
            _handle: handle,
        })
    }

    /// Pull a fresh keypair from the pool, or generate one immediately if the pool is empty.
    pub fn get(&self) -> X25519Keypair {
        let mut rx = self.receiver.lock();
        match rx.try_recv() {
            Ok(kp) => kp,
            Err(_) => X25519Keypair::generate(),
        }
    }
}

/// Global ephemeral key pool lazy initializer.
pub static GLOBAL_POOL_ONCE: tokio::sync::OnceCell<Arc<EphemeralKeyPool>> =
    tokio::sync::OnceCell::const_new();

/// Get a keypair from the global pool.
pub async fn get_ephemeral() -> X25519Keypair {
    let pool = GLOBAL_POOL_ONCE
        .get_or_init(|| async { EphemeralKeyPool::new(32) })
        .await;
    pool.get()
}
