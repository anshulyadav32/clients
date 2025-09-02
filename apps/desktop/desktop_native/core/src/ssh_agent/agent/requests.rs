use num_enum::TryFromPrimitive;

use crate::ssh_agent::agent::constants::ClientRequest;

#[derive(Debug)]
pub(crate) struct SshAgentRequest(Vec<u8>);
impl TryFrom<Vec<u8>> for SshAgentRequest {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(anyhow::anyhow!("Empty request"));
        }
        Ok(SshAgentRequest(value))
    }
}

impl SshAgentRequest {
    pub fn request_type(&self) -> Result<ClientRequest, anyhow::Error> {
        ClientRequest::try_from_primitive(self.0[0]).map_err(|e| {
            eprintln!("[SSH Agent] Error while parsing request type: {}", e);
            anyhow::anyhow!("Failed to parse request type")
        })
    }

    pub fn request_body(&self) -> &[u8] {
        &self.0[1..]
    }
}
