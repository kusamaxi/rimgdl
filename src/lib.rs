// lib.rs
use cfg_if::cfg_if;
pub mod app;
pub mod error_template;
pub mod fileserv;
use pgp::composed::{Deserializable, Message};
use pgp::errors::Result;
use pgp::crypto::hash::Digest;
use sha2::Sha512;
use hex::encode;
use std::io::Cursor;
use tokio::io::AsyncReadExt;
use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;

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


#[wasm_bindgen]
pub fn verify_file_sha512(file_data: Uint8Array, expected_sha512: &str) -> bool {
    let file_data = file_data.to_vec();
    verify_file_sha512_internal(&file_data, expected_sha512)
}

pub fn verify_file_sha512_internal(file_data: &[u8], expected_sha512: &str) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(file_data);
    let result = hasher.finalize();
    let result_hex = encode(result);
    result_hex == expected_sha512
}

#[wasm_bindgen]
pub async fn verify_gpg_signature(signed_data: Uint8Array, signature: Uint8Array, public_key: Uint8Array) -> Result<bool, JsValue> {
    let signed_data = signed_data.to_vec();
    let signature = signature.to_vec();
    let public_key = public_key.to_vec();

    verify_gpg_signature_internal(&signed_data, &signature, &public_key)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

pub async fn verify_gpg_signature_internal(
    signed_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    let signed_data = Cursor::new(signed_data);
    let signature = Cursor::new(signature);
    let public_key = pgp::packet::key::Public::from_bytes(public_key)?;

    let mut verifier = pgp::Verifier::from_buffer(public_key, signature)?;
    let mut buffer = Vec::new();
    verifier.read_to_end(&mut buffer).await?;

    Ok(buffer.as_slice() == signed_data.get_ref().to_slice())
}
