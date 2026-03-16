fn main() {
    uniffi::generate_scaffolding("./src/zero.udl").expect("Failed to generate uniffi bindings");
}
