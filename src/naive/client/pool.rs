use std::sync::{Arc, Weak, atomic::Ordering};

use anyhow::{Context, Result};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};

use super::Session;

pub(super) struct SessionPool {
    pub(super) sessions: Mutex<Vec<Arc<Session>>>,
    pub(super) slots: Arc<Semaphore>,
    pub(super) changed: Arc<Notify>,
    pub(super) pending: Arc<Semaphore>,
}

pub(super) struct PoolPolicy;

impl PoolPolicy {
    pub(super) const CONNECTIONS: usize = 4;
    pub(super) const STREAMS: usize = 64;
    pub(super) const PENDING: usize = 128;
}

pub(super) enum Assignment {
    Stream(Arc<Session>, StreamPermit),
    Connection(Slot),
    Unavailable,
}

pub(super) enum Allocation {
    Any,
    Available,
    Existing,
    Waiting,
    Retry,
}

pub(super) struct Slot {
    pub(super) permit: Option<OwnedSemaphorePermit>,
    pub(super) changed: Arc<Notify>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.changed.notify_waiters();
    }
}

pub(super) struct StreamPermit {
    pub(super) permit: Option<OwnedSemaphorePermit>,
    pub(super) changed: Arc<Notify>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.changed.notify_waiters();
    }
}

impl SessionPool {
    pub(super) fn new() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(PoolPolicy::CONNECTIONS)),
            changed: Arc::new(Notify::new()),
            pending: Arc::new(Semaphore::new(PoolPolicy::PENDING)),
        }
    }

    pub(super) fn enter(&self) -> Result<OwnedSemaphorePermit> {
        self.pending
            .clone()
            .try_acquire_owned()
            .context("upstream CONNECT queue full")
    }

    pub(super) async fn assign(
        &self,
        allocation: Allocation,
        excluded: &[Weak<Session>],
    ) -> Assignment {
        let mut retiring: Option<Weak<Option<Slot>>> = None;
        let eligible = |session: &Arc<Session>| {
            !excluded
                .iter()
                .any(|failed| failed.as_ptr() == Arc::as_ptr(session))
        };
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut sessions = self.sessions.lock().await;
            if matches!(allocation, Allocation::Retry)
                && let Some(failed) = excluded.last()
                && let Some(session) = failed.upgrade()
                && !session.usable()
                && session.active() == 0
            {
                // Cleanup may remove this session before its transport releases the slot.
                retiring = Some(Arc::downgrade(&session._slot));
            }
            sessions.retain(|session| session.usable() || session.active() > 0);
            let available = sessions
                .iter()
                .filter(|session| eligible(session))
                .find_map(|session| {
                    session
                        .try_acquire()
                        .map(|permit| (session.clone(), permit))
                });
            if let Some((session, permit)) = available {
                drop(sessions);
                return Assignment::Stream(session, permit);
            }
            if matches!(allocation, Allocation::Available)
                || matches!(allocation, Allocation::Existing)
                    && !sessions
                        .iter()
                        .any(|session| session.usable() && eligible(session))
            {
                return Assignment::Unavailable;
            }
            if matches!(allocation, Allocation::Retry)
                && self.slots.available_permits() == 0
                && retiring
                    .as_ref()
                    .is_none_or(|lease| lease.strong_count() == 0)
            {
                // Retire this request's failed session before considering unrelated sessions.
                let preferred_index = excluded.last().and_then(|failed| {
                    sessions
                        .iter()
                        .position(|session| failed.ptr_eq(&Arc::downgrade(session)))
                });
                let index = match preferred_index {
                    Some(index) => (sessions[index].active() == 0).then_some(index),
                    None => sessions.iter().position(|session| session.active() == 0),
                };
                if let Some(index) = index {
                    let session = sessions.swap_remove(index);
                    session.draining.store(true, Ordering::Relaxed);
                    retiring = Some(Arc::downgrade(&session._slot));
                    self.changed.notify_waiters();
                }
            }
            let slot = (!matches!(allocation, Allocation::Existing | Allocation::Waiting))
                .then(|| {
                    self.slots
                        .clone()
                        .try_acquire_owned()
                        .ok()
                        .map(|permit| Slot {
                            permit: Some(permit),
                            changed: self.changed.clone(),
                        })
                })
                .flatten();
            drop(sessions);
            if let Some(slot) = slot {
                return Assignment::Connection(slot);
            }
            notified.await;
        }
    }

    pub(super) async fn publish(&self, session: Arc<Session>) {
        self.sessions.lock().await.push(session);
        self.changed.notify_waiters();
    }
}
