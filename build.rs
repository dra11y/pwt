use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure directories exist
    fs::create_dir_all("src/generated")?;
    fs::create_dir_all("tests/generated")?;

    // Generate main protobuf files
    protobuf_codegen::Codegen::new()
        .out_dir("src/generated")
        .include(".")
        .include("google")
        .input("pwt.proto")
        .run()?;

    // Generate test protobuf files
    protobuf_codegen::Codegen::new()
        .out_dir("tests/generated")
        .include(".")
        .input("tests/fixtures/test.proto")
        .run()?;

    Ok(())
}
