use std::io::Read;

use byteorder::ReadBytesExt;
use bytes::{Buf, Bytes};
use futures::AsyncReadExt;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use ssh_encoding::Reader;

use crate::ssh_agent::agent::agent::SshPublicKey;

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(u8)]
pub enum ClientRequest {
    SSH_AGENTC_REQUEST_IDENTITIES = 11,
    SSH_AGENTC_SIGN_REQUEST = 13,
    SSH_AGENTC_EXTENSION = 27,
    #[default]
    SSH_AGENTC_INVALID = 0,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SshSignFlags {
    SSH_AGENT_RSA_SHA2_256 = 2,
    SSH_AGENT_RSA_SHA2_512 = 4,
}

#[derive(Debug)]
pub(crate) enum AgentRequest {
    IdentitiesRequest,
    SignRequest(SshSignRequest),
}

impl TryFrom<Vec<u8>> for AgentRequest {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(anyhow::anyhow!("Empty request"));
        }

        let request_type = ClientRequest::try_from_primitive(value[0])
            .map_err(|_| anyhow::anyhow!("Failed to parse request type"))?;
        let request_body = value[1..].to_vec();

        match request_type {
            ClientRequest::SSH_AGENTC_REQUEST_IDENTITIES => Ok(AgentRequest::IdentitiesRequest),
            ClientRequest::SSH_AGENTC_SIGN_REQUEST => {
                let sign_request = SshSignRequest::try_from(request_body.as_slice())
                    .map_err(|e| anyhow::anyhow!("Failed to parse sign request: {e}"))?;
                Ok(AgentRequest::SignRequest(sign_request))
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported request type: {:?}",
                request_type
            )),
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
