fn main() {
    println!("cargo:rustc-link-lib=pam");

    let bindings = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <security/pam_modules.h>")
        .allowlist_function("pam_get_user")
        .allowlist_function("pam_set_item")
        .allowlist_type("pam_handle_t")
        .allowlist_type("pam_handle")
        .allowlist_var("PAM_USER")
        .generate()
        .expect("unable to generate PAM bindings");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("pam.rs")).unwrap();
}
