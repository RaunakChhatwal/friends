use anyhow::Result;
use glob::glob;

fn main() -> Result<()> {
    let proto_files = glob("proto/**/*.proto")?.collect::<Result<Vec<_>, _>>()?;
    tonic_build::configure().compile_protos(&proto_files, &["./"]).map_err(Into::into)
}
