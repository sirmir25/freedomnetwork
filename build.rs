//! Build script: compiles the C++ bypass_core library and links it into the Rust binary.

fn main() {
    println!("cargo:rerun-if-changed=cpp/src/tls.cpp");
    println!("cargo:rerun-if-changed=cpp/src/http.cpp");
    println!("cargo:rerun-if-changed=cpp/include/bypass_core.h");

    cc::Build::new()
        .cpp(true)
        .files(["cpp/src/tls.cpp", "cpp/src/http.cpp"])
        .include("cpp/include")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .compile("bypass_core");
}
