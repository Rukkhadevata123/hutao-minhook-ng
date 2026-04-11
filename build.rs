fn main() {
    println!("cargo:rerun-if-changed=src/hutao_seh_stub.c");

    cc::Build::new()
        .file("src/hutao_seh_stub.c")
        .compile("hutao_seh_stub");
}
