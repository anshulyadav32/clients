use bitwarden_russh::ssh_agent::Agent;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::rngs::OsRng;
use ssh_encoding::Encode;

use crate::ssh_agent::agent::agent::SshKeyPair;

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u8)]
pub enum AgentReply {
    SSH_AGENT_FAILURE = 5,
    SSH_AGENT_SUCCESS = 6,
    SSH_AGENT_EXTENSION_FAILURE = 28,
    SSH_AGENT_IDENTITIES_ANSWER = 12,
    SSH_AGENT_SIGN_RESPONSE = 14,
    #[default]
    SSH_AGENT_INVALID = 0,
}

pub(crate) struct AgentIdentitiesReply {
    keys: Vec<SshKeyPair>,
}

impl AgentIdentitiesReply {
    pub fn new(keys: Vec<SshKeyPair>) -> Self {
        Self { keys }
    }

    pub fn encode(&self) -> Result<SshReplyFrame, ssh_encoding::Error> {
        // The Reply frame consists of the number of keys, followed by each key's public key and name
        let mut reply_message = Vec::new();
        (self.keys.len() as u32).encode(&mut reply_message)?;
        for key in &self.keys {
            key.public_key.encode(&mut reply_message)?;
            key.name.encode(&mut reply_message)?;
        }

        Ok(SshReplyFrame::new(
            AgentReply::SSH_AGENT_IDENTITIES_ANSWER,
            reply_message,
        ))
    }
}

pub(crate) struct AgentSignReply {}
impl AgentSignReply {
    pub fn new() -> Self {
        let rsa_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
            .expect("Failed to generate a key");
        rsa_key
            .sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(), b"test")
            .unwrap();
        Self {}
    }
}

pub(crate) struct AgentFailure;
impl AgentFailure {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<AgentFailure> for SshReplyFrame {
    type Error = ssh_encoding::Error;

    fn try_from(_value: AgentFailure) -> Result<Self, Self::Error> {
        Ok(SshReplyFrame::new(
            AgentReply::SSH_AGENT_EXTENSION_FAILURE,
            Vec::new(),
        ))
    }
}

pub struct SshReplyFrame {
    raw_frame: Vec<u8>,
}

impl SshReplyFrame {
    pub fn new(reply: AgentReply, payload: Vec<u8>) -> Self {
        let mut raw_frame = Vec::new();
        Into::<u8>::into(reply)
            .encode(&mut raw_frame)
            .expect("Encoding into Vec cannot fail");
        raw_frame.extend_from_slice(&payload);
        Self { raw_frame }
    }
}

impl Into<Vec<u8>> for &SshReplyFrame {
    fn into(self) -> Vec<u8> {
        self.raw_frame.clone()
    }
}
