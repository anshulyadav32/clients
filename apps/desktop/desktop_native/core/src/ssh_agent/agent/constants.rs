use num_enum::{IntoPrimitive, TryFromPrimitive};

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
