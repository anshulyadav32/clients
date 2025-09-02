use futures::{Stream, StreamExt};
use num_enum::TryFromPrimitive;
use rand::rngs::OsRng;
use ssh_encoding::{Decode, Encode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
};
use tokio_util::sync::CancellationToken;

use crate::ssh_agent::{
    agent::{
        agent::PublicKey,
        constants::ClientRequest,
        replies::{AgentIdentitiesReply, SshReplyFrame},
    },
    peerinfo::models::PeerInfo,
};

// Serves a single SSH listener, handling many connections. Only one connection can happen concurrently.
pub async fn serve_listener<PeerStream, Listener>(
    mut listener: Listener,
    cancellation_token: CancellationToken,
) -> Result<(), anyhow::Error>
where
    PeerStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    Listener: Stream<Item = tokio::io::Result<(PeerStream, PeerInfo)>> + Unpin,
{
    loop {
        select! {
            _ = cancellation_token.cancelled() => {
                break;
            }
            Some(Ok((stream, info))) = listener.next() => {
                println!("[SSH Agent] Accepting connection");
                let mut stream = AsyncStreamWrapper::new(stream);
                let response = handle_request(&mut stream).await.unwrap();
                let response = response.encode().unwrap();
                println!("Response: {:?}", response);
                stream.write_reply(&response).await.unwrap();
            }
        }
    }
    Ok(())
}

const PRIVATE_ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBDUDO7ChZIednIJxGA95T/ZTyREftahrFEJM/eeC8mmAAAAKByJoOYciaD
mAAAAAtzc2gtZWQyNTUxOQAAACBDUDO7ChZIednIJxGA95T/ZTyREftahrFEJM/eeC8mmA
AAAEBQK5JpycFzP/4rchfpZhbdwxjTwHNuGx2/kvG4i6xfp0NQM7sKFkh52cgnEYD3lP9l
PJER+1qGsUQkz954LyaYAAAAHHF1ZXh0ZW5ATWFjQm9vay1Qcm8tMTYubG9jYWwB
-----END OPENSSH PRIVATE KEY-----";

fn parse_key_safe(pem: &str) -> Result<ssh_key::private::PrivateKey, anyhow::Error> {
    match ssh_key::private::PrivateKey::from_openssh(pem) {
        Ok(key) => match key.public_key().to_bytes() {
            Ok(_) => Ok(key),
            Err(e) => Err(anyhow::Error::msg(format!(
                "Failed to parse public key: {e}"
            ))),
        },
        Err(e) => Err(anyhow::Error::msg(format!("Failed to parse key: {e}"))),
    }
}

async fn handle_request(
    stream: &mut AsyncStreamWrapper<impl AsyncRead + AsyncWrite + Send + Sync + Unpin>,
) -> Result<SshReplyFrame, anyhow::Error> {
    let message = SshAgentRequest::try_from(stream.read_message().await?)?;
    match message.request_type()? {
        ClientRequest::SSH_AGENTC_REQUEST_IDENTITIES => {
            println!("[SSH Agent] Received REQUEST_IDENTITIES");
            // Todo: Implement fetching from agent
            let key = parse_key_safe(PRIVATE_ED25519_KEY).unwrap();
            let keys = [PublicKey {
                public_key_bytes: key.public_key().to_bytes().unwrap(),
                name: "abc".into(),
            }];
            AgentIdentitiesReply::new(keys.to_vec())
                .encode()
                .map_err(|e| anyhow::anyhow!("Failed to encode identities reply: {e}"))
        }
        _ => {
            todo!()
        }
    }
}

struct AsyncStreamWrapper<PeerStream>
where
    PeerStream: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    stream: PeerStream,
}

impl<PeerStream> AsyncStreamWrapper<PeerStream>
where
    PeerStream: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    pub fn new(stream: PeerStream) -> Self {
        Self { stream }
    }

    pub async fn read_u32(&mut self) -> Result<u32, anyhow::Error> {
        let mut buf = [0u8; 4];
        self.stream.read_exact(&mut buf).await?;
        let num = u32::decode(&mut buf.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to decode u32: {}", e))?;
        Ok(num)
    }

    pub async fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, anyhow::Error> {
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    pub async fn read_message(&mut self) -> Result<Vec<u8>, anyhow::Error> {
        // An SSH agent message consists of a 32 bit integer denoting the length, followed by that many bytes
        let length = self.read_u32().await? as usize;
        self.read_vec(length).await
    }

    pub async fn write_reply(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.stream.write_all(data).await?;
        Ok(())
    }
}

#[derive(Debug)]
struct SshAgentRequest(Vec<u8>);
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
