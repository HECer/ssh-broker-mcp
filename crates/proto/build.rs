 fn main() -> Result<(), Box<dyn std::error::Error>> {
     tonic_build::configure()
         .build_server(true)
         .build_client(true)
         .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
         .compile(&["proto/sshbroker/v1/sshbroker.proto"], &["proto"])?;
     Ok(())
 }
