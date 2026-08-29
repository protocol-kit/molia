fn main() {
    println!("cargo:rerun-if-changed=proto/molia.proto");
    let fds = protox::compile(["proto/molia.proto"], ["proto"]).expect("protox");
    prost_build::Config::new()
        .bytes(["."])
        .compile_fds(fds)
        .expect("prost compile");
}