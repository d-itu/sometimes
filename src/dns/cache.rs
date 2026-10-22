use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ahash::RandomState as AHashState;
use anyhow::Result;
use lru::LruCache;

use super::packet::{cache_ttls, with_id};

struct Entry {
    packet: Vec<u8>,
    cached_at: Instant,
    expires: Instant,
    ttl_offsets: Vec<usize>,
}

pub(super) struct ResponseCache(Mutex<LruCache<Vec<u8>, Arc<Entry>, AHashState>>);

impl ResponseCache {
    pub(super) fn new(size: NonZeroUsize) -> Self {
        Self(Mutex::new(LruCache::with_hasher(
            size,
            AHashState::default(),
        )))
    }

    pub(super) fn get(&self, request: &[u8]) -> Option<Result<Vec<u8>>> {
        let now = Instant::now();
        let entry = self
            .0
            .lock()
            .unwrap()
            .get(request.get(2..)?)
            .filter(|entry| entry.expires > now)
            .cloned()?;
        let mut response = with_id(&entry.packet, request);
        if let Ok(ref mut packet) = response {
            let age = now.duration_since(entry.cached_at);
            let seconds = age.as_secs() + u64::from(age.subsec_nanos() != 0);
            let seconds = u32::try_from(seconds).unwrap_or(u32::MAX);
            for &offset in &entry.ttl_offsets {
                let original =
                    u32::from_be_bytes(entry.packet[offset..offset + 4].try_into().unwrap());
                packet[offset..offset + 4]
                    .copy_from_slice(&original.saturating_sub(seconds).to_be_bytes());
            }
        }
        Some(response)
    }

    pub(super) fn insert(&self, request: &[u8], response: &[u8]) {
        if let Some((ttl, ttl_offsets)) = cache_ttls(response) {
            let cached_at = Instant::now();
            let key = request[2..].to_vec();
            let entry = Arc::new(Entry {
                packet: response.to_vec(),
                cached_at,
                expires: cached_at + Duration::from_secs(ttl.into()),
                ttl_offsets,
            });
            self.0.lock().unwrap().put(key, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::packet::make_query;

    #[test]
    fn cached_ttls_decrease_without_touching_opt() {
        let request = make_query("example.com", 1);
        let mut response = request.clone();
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&10u32.to_be_bytes());
        response.extend_from_slice(&[0, 4, 127, 0, 0, 1]);
        response.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0x80, 0, 0, 0, 0]);
        let cache = ResponseCache::new(NonZeroUsize::new(2).unwrap());
        cache.insert(&request, &response);
        Arc::get_mut(cache.0.lock().unwrap().get_mut(&request[2..]).unwrap())
            .unwrap()
            .cached_at -= Duration::from_secs(2);
        let mut other = request.clone();
        other[..2].copy_from_slice(&[0x12, 0x34]);
        let reply = cache.get(&other).unwrap().unwrap();
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        let (ttl, offsets) = cache_ttls(&response).unwrap();
        assert_eq!(ttl, 10);
        assert_eq!(offsets.len(), 1);
        assert_eq!(
            u32::from_be_bytes(reply[offsets[0]..offsets[0] + 4].try_into().unwrap()),
            7
        );
        assert_eq!(&reply[offsets[0] + 10..], &response[offsets[0] + 10..]);
    }
}
