//! v0.55.1: object-storage backend for substrate bytes.
//!
//! Bytes go to S3-compatible object storage at publish time. The live
//! snapshot endpoint reconstructs frontier state from event/projection
//! tables, while `GET /entries/:vfr/snapshot?redirect=cdn` can return a
//! 302 redirect to the storage URL for immutable export reads.
//!
//! Production runs against [Tigris](https://www.tigrisdata.com/) (Fly's
//! S3-flavoured offering) but the same code speaks to CloudFlare R2 or
//! AWS S3 by changing only the endpoint URL. The whole config is
//! env-driven, no code change needed to swap providers.
//!
//! ## Doctrine
//!
//! - Content-addressed: keys are `sha256(canonical_json)`, the same
//!   `latest_snapshot_hash` the publisher signed into the manifest.
//!   Same bytes map to the same key, no matter who uploads.
//! - Public-read: substrate is meant for the world to pull. The bucket
//!   ACL grants anonymous GET. Writes are gated by the hub's
//!   signature-verifying `POST /entries`.
//! - Hub uploads, CDN serves: the hub puts; clients get directly. The
//!   hub is never in the bytes path on reads.

use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::primitives::ByteStream;
use std::env;

/// Object-storage handle for the hub. Cheap to clone (the underlying
/// `aws_sdk_s3::Client` shares an HTTP connection pool internally).
#[derive(Clone)]
pub struct Storage {
    client: Client,
    bucket: String,
    /// Public-read URL prefix. Tigris uses
    /// `https://fly.storage.tigris.dev/<bucket>` by default; can be a
    /// custom domain like `https://substrate.vela.science`. Keys are
    /// appended as `<prefix>/<snapshot_hash>`.
    public_url_prefix: String,
}

/// Build a Storage handle from environment variables. Returns `None` if
/// the bucket name is unset. The hub still serves live event/projection
/// reads, but publish-time snapshot exports and CDN redirects are
/// disabled.
///
/// Required env (all set automatically by `flyctl storage create`):
///   AWS_ACCESS_KEY_ID
///   AWS_SECRET_ACCESS_KEY
///   AWS_ENDPOINT_URL_S3   (e.g. https://fly.storage.tigris.dev)
///   AWS_REGION            (Tigris uses "auto"; R2 uses "auto"; AWS uses real region)
///   BUCKET_NAME
///
/// Optional:
///   VELA_HUB_PUBLIC_BLOB_URL_PREFIX — override the public URL prefix
///   (use this to front the bucket with a CDN / custom domain).
pub async fn from_env() -> Option<Storage> {
    let bucket = env::var("BUCKET_NAME").ok()?;
    let access_key = env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    let endpoint = env::var("AWS_ENDPOINT_URL_S3").ok()?;
    let region = env::var("AWS_REGION").unwrap_or_else(|_| "auto".to_string());

    let credentials = Credentials::new(
        access_key,
        secret_key,
        None, // no session token (Tigris uses long-lived keys)
        None,
        "vela-hub-env",
    );

    let s3_config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(&endpoint)
        // Required for S3-compatible providers that don't support
        // virtual-hosted-style addressing on custom domains.
        .force_path_style(true)
        .credentials_provider(credentials)
        .build();
    let client = Client::from_conf(s3_config);

    // Default the public URL prefix to subdomain-style addressing —
    // the only form that works for anonymous reads on Tigris (and the
    // canonical form on AWS S3 / CloudFlare R2 too). E.g.
    //   endpoint=https://fly.storage.tigris.dev, bucket=vela-substrate
    // becomes
    //   https://vela-substrate.fly.storage.tigris.dev
    // The operator can override via VELA_HUB_PUBLIC_BLOB_URL_PREFIX
    // when fronting the bucket with a CDN / custom domain.
    let public_url_prefix = env::var("VELA_HUB_PUBLIC_BLOB_URL_PREFIX").unwrap_or_else(|_| {
        let trimmed = endpoint.trim_end_matches('/');
        let (scheme, host) = if let Some(rest) = trimmed.strip_prefix("https://") {
            ("https", rest)
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            ("http", rest)
        } else {
            ("https", trimmed)
        };
        format!("{scheme}://{}.{host}", bucket.trim_matches('/'))
    });

    Some(Storage {
        client,
        bucket,
        public_url_prefix,
    })
}

impl Storage {
    /// Upload the substrate bytes content-addressed by `snapshot_hash`.
    /// Returns the public URL where the bytes can be fetched. Idempotent:
    /// re-uploading the same key with the same content is a no-op for
    /// callers (we don't HEAD-check first; we just PUT — the underlying
    /// store handles overwrite-with-identical-content as a normal write).
    pub async fn put(
        &self,
        snapshot_hash: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<String, String> {
        let key = snapshot_hash.to_string();
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type(content_type)
            // Note: the bucket itself is created public-read by
            // `flyctl storage create --public`, so we don't set per-
            // object ACLs (Tigris doesn't support them anyway).
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| format!("put_object {}/{}: {e}", self.bucket, key))?;
        Ok(self.public_url_for(snapshot_hash))
    }

    /// Compute the public URL for a key without making any request.
    /// Useful for checking whether a key would resolve before uploading.
    pub fn public_url_for(&self, snapshot_hash: &str) -> String {
        format!(
            "{}/{}",
            self.public_url_prefix.trim_end_matches('/'),
            snapshot_hash
        )
    }

    /// HEAD the object to check whether it already exists. Cheap (no
    /// body transfer); used by the backfill to skip already-uploaded
    /// snapshots.
    pub async fn exists(&self, snapshot_hash: &str) -> Result<bool, String> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(snapshot_hash)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let s = e.to_string();
                if s.contains("NotFound") || s.contains("404") {
                    Ok(false)
                } else {
                    Err(format!(
                        "head_object {}/{}: {e}",
                        self.bucket, snapshot_hash
                    ))
                }
            }
        }
    }
}
