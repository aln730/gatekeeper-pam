fn main() {
    println!("cargo:rustc-link-lib=pam");

    let bindings = bindgen::Builder::default()
        .header_contents(
            "wrapper.h",
            "#include <security/pam_modules.h>\n#include <security/pam_ext.h>",
        )
        .allowlist_function("pam_get_user")
        .allowlist_function("pam_set_item")
        .allowlist_function("pam_get_item")
        .allowlist_function("pam_prompt")
        .allowlist_type("pam_handle_t")
        .allowlist_type("pam_handle")
        .allowlist_type("pam_conv")
        .allowlist_type("pam_message")
        .allowlist_type("pam_response")
        .allowlist_var("PAM_USER")
        .allowlist_var("PAM_CONV")
        .allowlist_var("PAM_TEXT_INFO")
        .allowlist_var("PAM_PROMPT_ECHO_OFF")
        .generate()
        .expect("unable to generate PAM bindings");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("pam.rs")).unwrap();
}
