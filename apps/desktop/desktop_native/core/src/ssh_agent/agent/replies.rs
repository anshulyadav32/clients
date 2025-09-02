use ssh_encoding::Encode;

use crate::ssh_agent::agent::{agent::PublicKey, constants::AgentReply};

pub(crate) struct AgentIdentitiesReply {
    keys: Vec<PublicKey>,
}

impl AgentIdentitiesReply {
    pub fn new(keys: Vec<PublicKey>) -> Self {
        Self { keys }
    }

    pub fn encode(&self) -> Result<SshReplyFrame, ssh_encoding::Error> {
        // The Reply frame consists of the number of keys, followed by each key's public key and name
        let mut reply_message = Vec::new();
        (self.keys.len() as u32).encode(&mut reply_message)?;
        for key in &self.keys {
            key.public_key_bytes.encode(&mut reply_message)?;
            key.name.encode(&mut reply_message)?;
        }

        Ok(SshReplyFrame::new(
            AgentReply::SSH_AGENT_IDENTITIES_ANSWER,
            reply_message,
        ))
    }
}

pub(crate) struct SshReplyFrame {
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

    pub fn encode(&self) -> Result<Vec<u8>, ssh_encoding::Error> {
        let mut message = Vec::new();
        self.raw_frame.len().encode(&mut message)?;
        message.extend_from_slice(&self.raw_frame);
        Ok(message)
    }
}
