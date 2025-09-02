use futures::{Stream, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
};
use tokio_util::sync::CancellationToken;

use crate::ssh_agent::{
    agent::{
        agent::PublicKey,
        async_stream_wrapper::AsyncStreamWrapper,
        constants::ClientRequest,
        replies::{AgentIdentitiesReply, SshReplyFrame},
        requests::SshAgentRequest,
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
                if let Err(e) =  handle_request(&mut stream).await {
                    eprintln!("[SSH Agent] Error handling request: {e}");
                }
            }
        }
    }
    Ok(())
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

// Debug/test code:
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
