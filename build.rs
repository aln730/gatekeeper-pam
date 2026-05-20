fn main() {
    println!("cargo:rustc-link-lib=pam");

    let bindings = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <security/pam_modules.h>")
        .allowlist_function("pam_.*")
        .allowlist_type("pam_.*")
        .allowlist_var("PAM_.*")
        .generate()
        .expect("unable to generate PAM bindings");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("pam.rs")).unwrap();
}
