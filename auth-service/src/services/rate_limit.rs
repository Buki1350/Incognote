//! In-memory brute-force protection.
//! This avoids extra DB tables while still protecting login endpoints.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Entry {
    failures: Vec<Instant>,
    blocked_until: Option<Instant>,
}

impl Entry {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
            blocked_until: None,
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    entries: Mutex<HashMap<String, Entry>>,
    max_attempts: usize,
    window: Duration,
    lockout: Duration,
}

impl RateLimiter {
    pub fn secure_defaults() -> Self {
        Self::new(
            5,
            Duration::from_secs(15 * 60),
            Duration::from_secs(15 * 60),
        )
    }

    pub fn new(max_attempts: usize, window: Duration, lockout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_attempts,
            window,
            lockout,
        }
    }

    pub fn is_blocked(&self, username: &str, ip: &str) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let key = Self::key(username, ip);
        let now = Instant::now();

        let Some(entry) = entries.get_mut(&key) else {
            return false;
        };

        prune_entry(entry, now, self.window);

        entry
            .blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
    }

    pub fn record_failure(&self, username: &str, ip: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let key = Self::key(username, ip);
        let now = Instant::now();

        let entry = entries.entry(key).or_insert_with(Entry::new);
        prune_entry(entry, now, self.window);
        entry.failures.push(now);

        if entry.failures.len() >= self.max_attempts {
            entry.blocked_until = Some(now + self.lockout);
        }
    }

    pub fn record_success(&self, username: &str, ip: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let key = Self::key(username, ip);
        entries.remove(&key);
    }

    fn key(username: &str, ip: &str) -> String {
        format!("{}|{}", username.trim().to_lowercase(), ip.trim())
    }
}

fn prune_entry(entry: &mut Entry, now: Instant, window: Duration) {
    entry
        .failures
        .retain(|attempt| now.duration_since(*attempt) <= window);

    if entry
        .blocked_until
        .is_some_and(|blocked_until| blocked_until <= now)
    {
        entry.blocked_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;
    use std::{thread, time::Duration};

    #[test]
    fn limiter_blocks_after_threshold() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60), Duration::from_millis(50));

        limiter.record_failure("alice", "1.2.3.4");
        assert!(!limiter.is_blocked("alice", "1.2.3.4"));

        limiter.record_failure("alice", "1.2.3.4");
        assert!(limiter.is_blocked("alice", "1.2.3.4"));

        thread::sleep(Duration::from_millis(55));
        assert!(!limiter.is_blocked("alice", "1.2.3.4"));
    }
}
