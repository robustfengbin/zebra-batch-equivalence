//! The batching middleware itself — who ends up in a batch with whom.
//!
//! Every other module in this crate reaches a verifier through its backend
//! crate, where the batch *mathematics* lives. This one covers the other half:
//! `tower-batch-control`, the middleware that decides **which items share a
//! batch**. It is Zebra's own crate, M1 never touched it, and the grant names it
//! by name as a coverage target.
//!
//! The difference from every assertion elsewhere in this crate is what draws the
//! batch boundary. In `tests/` the boundaries are ours: we choose the groups, the
//! permutations, the sub-batches, synchronously and deterministically. Here the
//! boundary is drawn by a real scheduler from **arrival timing** — a `tokio::select!`
//! between "another item arrived" and "the batch timer expired"
//! (`worker.rs:204`). That is the only path that reaches the 754 lines of
//! `worker.rs` + `service.rs`, and it is the only one where the grouping is not
//! something we decided.
//!
//! Which matters beyond coverage: batch membership is partly a function of
//! arrival order, and arrival order is partly a function of what the network
//! delivers. So "which items share a batch" is not entirely under the node's
//! control, and the property that has to hold is that **it does not matter** —
//! no item's verdict may depend on who it was batched with.
//!
//! ## What this mirrors, and where it deliberately does not
//!
//! [`BatchService`] is the shape of Zebra's per-pool services (`halo2.rs`,
//! `sapling.rs`, `redjubjub.rs`, `groth16.rs`, `ed25519.rs`): hold a batch, hand
//! each caller a future, and broadcast one flushed result over a `watch` channel
//! to everyone who waited. Three deliberate differences, all in service of the
//! oracle rather than of performance:
//!
//! * **Seeded RNG, not `thread_rng()`.** Production hard-codes `thread_rng()`
//!   with no seam to inject a seed. A disagreement that cannot be reproduced
//!   cannot be cited, so the seed comes in through the constructor. This is the
//!   same reason M1 drives `orchard::BatchValidator` directly rather than Zebra's
//!   service.
//! * **Items accumulate and are verified at flush**, where production queues each
//!   item into the backend validator as it arrives. The set fed to the backend,
//!   and its order, are identical either way — and *when* an item is queued is
//!   already covered at per-item granularity by [`crate::verifier`]. What this
//!   module is asking about is the composition of the batch, not the timing of
//!   the enqueue.
//! * **Flush verifies synchronously** rather than on a `rayon` pool. Nothing here
//!   asserts anything about concurrency between batches; making the flush
//!   deterministic removes a source of noise from assertions that are about
//!   grouping.
//!
//! No modifications to Zebra: `Batch`, `BatchControl` and `RequestWeight` are the
//! crate's public API, and this drives them as a consumer.

use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::watch;
use tower::Service;
use tower_batch_control::{Batch, BatchControl, RequestWeight};

use crate::verifier::BatchVerifier;

/// Boxed error, matching what the middleware requires of a service.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Zebra's batch size limit, one constant shared by every batch verifier
/// (`zebra-consensus/src/primitives.rs:15`). Its comment says it is "for **any**
/// of the batch verifiers" — see [`BatchVerifier::item_weight`] for why that one
/// number does not mean one thing.
pub const MAX_BATCH_SIZE: usize = 64;

/// Zebra's batch latency limit (`primitives.rs:18`): how long an item may wait
/// for a batch to fill before the batch is flushed anyway.
pub const MAX_BATCH_LATENCY: Duration = Duration::from_millis(100);

/// One verification item on its way through the middleware, carrying the weight
/// its pool assigns it.
///
/// A newtype because `RequestWeight` is `tower-batch-control`'s trait and
/// `Arc<V::Item>` is not our type — but also because the weight is the point:
/// this is where a pool's [`BatchVerifier::item_weight`] becomes the number the
/// scheduler actually divides batches by.
pub struct Weighted<V: BatchVerifier> {
    item: Arc<V::Item>,
}

impl<V: BatchVerifier> Weighted<V> {
    /// Wrap an item for submission to a batched service.
    pub fn new(item: Arc<V::Item>) -> Self {
        Self { item }
    }

    /// The item itself.
    pub fn item(&self) -> &V::Item {
        &self.item
    }
}

impl<V: BatchVerifier> Clone for Weighted<V> {
    fn clone(&self) -> Self {
        Self {
            item: Arc::clone(&self.item),
        }
    }
}

impl<V: BatchVerifier> RequestWeight for Weighted<V> {
    fn request_weight(&self) -> usize {
        V::item_weight(&self.item)
    }
}

/// A record of how the scheduler actually divided the work: one entry per
/// flushed batch, holding that batch's item count, in flush order.
///
/// Exists because an assertion that batching does not change verdicts is
/// worthless unless the batching *changed*. Two submission patterns that both
/// happen to land in a single batch would satisfy every invariance assertion in
/// `tests/tower_batching.rs` while testing nothing — and, like most failures in
/// this project, would look exactly like a pass. So the tests read this and
/// assert the partitions differ before comparing verdicts.
#[derive(Clone, Default)]
pub struct BatchLog(Arc<Mutex<Vec<usize>>>);

impl BatchLog {
    /// Batch sizes in flush order.
    pub fn sizes(&self) -> Vec<usize> {
        self.0.lock().expect("batch log poisoned").clone()
    }

    /// How many batches have been flushed.
    pub fn count(&self) -> usize {
        self.0.lock().expect("batch log poisoned").len()
    }

    fn record(&self, size: usize) {
        self.0.lock().expect("batch log poisoned").push(size);
    }
}

/// The per-batch verdicts a flush broadcasts, shared by every future waiting on
/// that batch.
type Verdicts = Arc<Vec<bool>>;

/// The batched side of the middleware for any [`BatchVerifier`] — the shape
/// Zebra's per-pool verifier services have, with a seeded RNG so results
/// reproduce.
///
/// Wrap it in [`Batch`] (see [`batched`]) to get the scheduler; on its own it is
/// just a service that answers `Item` and `Flush`.
pub struct BatchService<V: BatchVerifier> {
    /// Items queued since the last flush, in arrival order.
    pending: Vec<Arc<V::Item>>,
    /// Broadcasts one flushed batch's per-item verdicts to every future waiting
    /// on it. A fresh channel per batch, so a future can only ever observe the
    /// result of the batch it was actually in.
    tx: watch::Sender<Option<Verdicts>>,
    ctx: &'static V::Context,
    seed: u64,
    log: BatchLog,
}

impl<V: BatchVerifier> BatchService<V> {
    /// A service verifying against `ctx`, with `seed` fixing the batch RNG.
    pub fn new(ctx: &'static V::Context, seed: u64) -> Self {
        Self::with_log(ctx, seed, BatchLog::default())
    }

    /// As [`Self::new`], recording each flushed batch's size into `log`.
    pub fn with_log(ctx: &'static V::Context, seed: u64, log: BatchLog) -> Self {
        let (tx, _) = watch::channel(None);
        Self {
            pending: Vec::new(),
            tx,
            ctx,
            seed,
            log,
        }
    }

    /// Take the pending batch and its channel, leaving a fresh, empty pair —
    /// mirroring `Verifier::take` in every Zebra verifier service.
    fn take(&mut self) -> (Vec<Arc<V::Item>>, watch::Sender<Option<Verdicts>>) {
        let pending = mem::take(&mut self.pending);
        let (tx, _) = watch::channel(None);
        let tx = mem::replace(&mut self.tx, tx);
        (pending, tx)
    }

    /// Verify one batch and broadcast its per-item verdicts.
    fn flush(&mut self) {
        let (pending, tx) = self.take();
        if pending.is_empty() {
            // Nothing waiting on this channel; an empty batch has no verdicts to
            // report. Sending an empty vector would be equally correct and
            // slightly more confusing.
            return;
        }
        self.log.record(pending.len());
        let refs: Vec<&V::Item> = pending.iter().map(|item| item.as_ref()).collect();
        let verdicts = V::validate_batch(&refs, self.ctx, self.seed);
        let _ = tx.send(Some(Arc::new(verdicts)));
    }
}

impl<V: BatchVerifier> Service<BatchControl<Weighted<V>>> for BatchService<V>
where
    V: 'static,
    V::Item: Send + Sync + 'static,
    V::Context: Sync,
{
    /// Whether this item verified. The middleware needs a `Service`, and a
    /// verdict per item is what the oracle is about; a mechanism failure (the
    /// batch never flushed) is the `Error` case and is not a verdict.
    type Response = bool;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<bool, BoxError>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: BatchControl<Weighted<V>>) -> Self::Future {
        match req {
            BatchControl::Item(weighted) => {
                // Position within *this* batch, which is how a broadcast verdict
                // finds its way back to the right caller.
                let index = self.pending.len();
                self.pending.push(weighted.item);
                let mut rx = self.tx.subscribe();

                Box::pin(async move {
                    rx.changed()
                        .await
                        .map_err(|_| "batch was dropped before it flushed")?;
                    let verdicts = rx
                        .borrow()
                        .clone()
                        .ok_or("batch flushed without producing verdicts")?;
                    verdicts
                        .get(index)
                        .copied()
                        .ok_or_else(|| BoxError::from("verdict missing for item in batch"))
                })
            }

            BatchControl::Flush => {
                self.flush();
                Box::pin(async { Ok(true) })
            }
        }
    }
}

impl<V: BatchVerifier> Drop for BatchService<V> {
    fn drop(&mut self) {
        // Same reason Zebra's services flush on drop: any future still waiting on
        // the current batch would otherwise wait forever.
        self.flush();
    }
}

/// A verifier behind the real batching middleware, with Zebra's production
/// limits.
///
/// Must be called from within a tokio runtime — [`Batch::new`] spawns the worker
/// that owns the scheduling loop.
pub fn batched<V: BatchVerifier + Send + 'static>(
    ctx: &'static V::Context,
    seed: u64,
) -> (Batch<BatchService<V>, Weighted<V>>, BatchLog)
where
    V::Item: Send + Sync + 'static,
    V::Context: Sync,
{
    batched_with(ctx, seed, MAX_BATCH_SIZE, MAX_BATCH_LATENCY)
}

/// A verifier behind the middleware with explicit limits, for tests that need to
/// force a particular batching regime (one batch, many batches, timer-driven
/// flushes).
///
/// `max_batches` is left at the production default of `None`, which resolves to
/// the current rayon thread count.
///
/// Returns the [`BatchLog`] alongside the service, because how the scheduler
/// divided the work is not incidental here — it is half of what the tower-layer
/// assertions are about.
pub fn batched_with<V: BatchVerifier + Send + 'static>(
    ctx: &'static V::Context,
    seed: u64,
    max_weight: usize,
    max_latency: Duration,
) -> (Batch<BatchService<V>, Weighted<V>>, BatchLog)
where
    V::Item: Send + Sync + 'static,
    V::Context: Sync,
{
    let log = BatchLog::default();
    let service = BatchService::<V>::with_log(ctx, seed, log.clone());
    (Batch::new(service, max_weight, None, max_latency), log)
}
