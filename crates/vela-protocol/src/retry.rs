//! Retry with exponential backoff for transient network failures.

use std::time::Duration;
use tokio::time::sleep;

/// Retry an async operation with exponential backoff.
/// Retries up to `max_retries` times with delays of 1s, 2s, 4s, 8s.
/// Only retries on errors, not on successful-but-wrong results.
pub async fn retry_with_backoff<F, Fut, T, E>(
    label: &str,
    max_retries: u32,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    loop {
        match operation().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                attempt += 1;
                if attempt > max_retries {
                    return Err(e);
                }
                let delay = Duration::from_secs(1 << (attempt - 1)); // 1s, 2s, 4s, 8s
                eprintln!(
                    "  [retry] {} failed (attempt {}/{}): {}. Retrying in {:?}...",
                    label, attempt, max_retries, e, delay
                );
                sleep(delay).await;
            }
        }
    }
}
