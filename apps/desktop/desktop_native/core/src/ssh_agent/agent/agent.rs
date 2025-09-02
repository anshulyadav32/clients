#[derive(Debug, Clone)]
pub struct PublicKey {
    pub public_key_bytes: Vec<u8>,
    pub name: String,
}

pub(crate) trait Agent {
    async fn list_keys(&self) -> Result<Vec<PublicKey>, anyhow::Error>;
}
