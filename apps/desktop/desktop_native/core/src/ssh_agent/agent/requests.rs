use byteorder::ReadBytesExt;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::ssh_agent::agent::agent::SshPublicKey;

/// `https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html#name-protocol-messages`
/// The different types of requests that a client can send to the SSH agent.
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u8)]
pub enum RequestType {
    /// `https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html#name-requesting-a-list-of-keys`
    /// Request the list of keys the agent is holding
    SSH_AGENTC_REQUEST_IDENTITIES = 11,
    /// `https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html#name-private-key-operations`
    /// Sign an authentication request or SSHSIG request
    SSH_AGENTC_SIGN_REQUEST = 13,
    /// `https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html#name-extension-mechanism`
    /// Handle vendor specific extensions such as session binding
    SSH_AGENTC_EXTENSION = 27,
    /// An invalid request
    #[default]
    SSH_AGENTC_INVALID = 0,
}

/// `https://www.ietf.org/archive/id/draft-miller-ssh-agent-11.html#name-signature-flags`
///
/// There are currently two flags defined which control which signature method
/// are used for RSA. These have no effect on other key types. If neither of these is defined,
/// RSA is used with SHA1, however this is deprecated and should not be used.
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SshSignFlags {
    SSH_AGENT_RSA_SHA2_256 = 2,
    SSH_AGENT_RSA_SHA2_512 = 4,
}

#[derive(Debug)]
pub(crate) enum Request {
    IdentitiesRequest,
    SignRequest(SshSignRequest),
}

impl TryFrom<Vec<u8>> for Request {
    type Error = anyhow::Error;

    // A protocol message consists of
    // uint32 length
    // byte type
    // byte[length-1] contents
    //
    // The length is already stripped of in the `async_stream_wrapper::read_message`, so
    // the message is just type|contents.
    fn try_from(message: Vec<u8>) -> Result<Self, Self::Error> {
        if message.is_empty() {
            return Err(anyhow::anyhow!("Empty request"));
        }

        let r#type = RequestType::try_from_primitive(message[0])
            .map_err(|_| anyhow::anyhow!("Failed to parse request type"))?;
        let contents = message[1..].to_vec();

        match r#type {
            RequestType::SSH_AGENTC_REQUEST_IDENTITIES => Ok(Request::IdentitiesRequest),
            RequestType::SSH_AGENTC_SIGN_REQUEST => {
                let sign_request = SshSignRequest::try_from(contents.as_slice())
                    .map_err(|e| anyhow::anyhow!("Failed to parse sign request: {e}"))?;
                Ok(Request::SignRequest(sign_request))
            }
            _ => Err(anyhow::anyhow!("Unsupported request type: {:?}", r#type)),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SshSignRequest {
    pub(crate) public_key: SshPublicKey,
    pub(crate) payload_to_sign: Vec<u8>,
    pub(crate) parsed_sign_request: ParsedSignRequest,
    flags: u32,
}

impl SshSignRequest {
    pub fn is_flag_set(&self, flag: SshSignFlags) -> bool {
        (self.flags & (flag as u32)) != 0
    }
}

impl TryFrom<&[u8]> for SshSignRequest {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let public_key = SshPublicKey::from(read_bytes(&mut value)?.to_vec());
        let data = read_bytes(&mut value)?;
        let parsed_sign_request = parse_request(&data)?;

        let flags = value
            .read_u32::<byteorder::BigEndian>()
            .map_err(|e| anyhow::anyhow!("Failed to read flags from sign request: {e}"))?;

        Ok(SshSignRequest {
            public_key: public_key,
            payload_to_sign: data,
            parsed_sign_request,
            flags,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ParsedSignRequest {
    SshSigRequest { namespace: String },
    SignRequest {},
}

pub(crate) fn parse_request(data: &[u8]) -> Result<ParsedSignRequest, anyhow::Error> {
    let mut data = Bytes::copy_from_slice(data);
    let magic_header = "SSHSIG";
    let header = data.split_to(magic_header.len());

    // sshsig; based on https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
    if header == magic_header.as_bytes() {
        let _version = data.get_u32();

        // read until null byte
        let namespace = data
            .into_iter()
            .take_while(|&x| x != 0)
            .collect::<Vec<u8>>();
        let namespace =
            String::from_utf8(namespace).map_err(|_| anyhow::anyhow!("Invalid namespace"))?;

        Ok(ParsedSignRequest::SshSigRequest { namespace })
    } else {
        Ok(ParsedSignRequest::SignRequest {})
    }
}

fn read_bytes(data: &mut &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let length = data
        .read_u32::<byteorder::BigEndian>()
        .map_err(|e| anyhow::anyhow!("Failed to read length: {e}"))?;
    let mut buf = vec![0; length as usize];
    std::io::Read::read_exact(data, &mut buf)
        .map_err(|e| anyhow::anyhow!("Failed to read exact bytes: {e}"))?;
    Ok(buf)
}
