use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use leptos::{create_memo, create_signal, component, Callback, IntoView, Scope, view};

use crate::read_file_content;
use crate::verify_file_sha512;
use crate::verify_gpg_signature;

#[component]
pub fn app(cx: Scope) -> impl IntoView {
    // provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context(cx);

    view! {
        cx,

        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <stylesheet id="leptos" href="/pkg/start-axum.css"/>

        // sets the document title
        <title text="expectchaos.com"/>
        // content for this welcome page
        <router>
            <main>
                <routes>
                    <route path="" view=|cx| view! { cx, <homepage/> }/>
                </routes>
            </main>
        </router>
    }
}

#[component]
fn HomePage(cx: Scope) -> impl IntoView {
    let iso_file = create_memo(cx);
    let iso_sha512_file = create_memo(cx);
    let iso_sig_file = create_memo(cx);
    let (error_message, set_error_message) = create_signal(cx, String::new());

    let on_submit = Callback::new(move |_| {
        spawn_local(async move {
            let iso_file = iso_file.get().dyn_into::<HtmlInputElement>().unwrap();
            let iso_sha512_file = iso_sha512_file.get().dyn_into::<HtmlInputElement>().unwrap();
            let iso_sig_file = iso_sig_file.get().dyn_into::<HtmlInputElement>().unwrap();

            let iso_file_content = read_file_content(&iso_file).await.unwrap();
            let iso_sha512_content = read_file_content(&iso_sha512_file).await.unwrap();
            let iso_sig_content = read_file_content(&iso_sig_file).await.unwrap();

            let sha512_check = verify_file_sha512(&iso_file_content, &iso_sha512_content);
            let gpg_check = verify_gpg_signature(&iso_file_content, &iso_sig_content).await;

            if sha512_check && gpg_check.unwrap_or(false) {
                set_error_message("Verification successful!");
            } else {
                set_error_message("Verification failed. Please check your files.");
            }
        });
    });

    view! { cx,
    <div>
        <h1>"Verify your ISO"</h1>
        <form on:submit=on_submit>
        <label>
        "ISO File: "
        <input ref=iso_file.clone() type="file"/>
        </label>
        <br/>
        <label>
        "ISO SHA512: "
        <input ref=iso_sha512_file.clone() type="file"/>
        </label>
        <br/>
        <label>
        "ISO Signature: "
        <input ref=iso_sig_file.clone() type="file"/>
        </label>
        <br/>
        <button type="submit">"Verify"</button>
        </form>
        <p>{error_message.get()}</p>
        </div>
    }
}


