// lib.rs
use cfg_if::cfg_if;
pub mod app;
pub mod error_template;
pub mod fileserv;
use rpgp::composed::{Deserializable, Message};
use rpgp::errors::Result;
use rpgp::crypto::hash::Digest;
use sha2::Sha512;
use hex::encode;
use std::io::Cursor;
use tokio::io::AsyncReadExt;

cfg_if! { if #[cfg(feature = "hydrate")] {
    use leptos::*;
    use wasm_bindgen::prelude::wasm_bindgen;
    use crate::app::*;

    #[wasm_bindgen]
    pub fn hydrate() {
        // initializes logging using the `log` crate
        _ = console_log::init_with_level(log::Level::Debug);
        console_error_panic_hook::set_once();

        leptos::mount_to_body(move |cx| {
            view! { cx, <App/> }
        });
    }
}}

pub fn verify_file_sha512(file_data: &[u8], expected_sha512: &str) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(file_data);
    let result = hasher.finalize();
    let result_hex = encode(result);
    result_hex == expected_sha512
}

pub async fn verify_gpg_signature(
    signed_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    let signed_data = Cursor::new(signed_data);
    let signature = Cursor::new(signature);
    let public_key = rpgp::packet::key::Public::from_bytes(public_key)?;

    let mut verifier = rpgp::Verifier::from_buffer(public_key, signature)?;
    let mut buffer = Vec::new();
    verifier.read_to_end(&mut buffer).await?;

    Ok(buffer.as_slice() == signed_data.get_ref().as_slice())
}
