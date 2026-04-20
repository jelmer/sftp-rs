//! russh transport glue for [`AsyncSftpClient`].
//!
//! The caller is responsible for establishing the SSH session (host-key
//! verification, authentication, proxy jumps, etc.) and opening a channel.
//! This module only takes the already-open channel, requests the `sftp`
//! subsystem, and wraps the resulting byte stream in an
//! [`AsyncSftpClient`].

use crate::r#async::AsyncSftpClient;
use russh::client::Msg;
use russh::{Channel, ChannelStream};
use tokio::io::WriteHalf;

/// The concrete [`AsyncSftpClient`] type returned when running over a russh
/// channel.
pub type RusshSftpClient = AsyncSftpClient<WriteHalf<ChannelStream<Msg>>>;

/// Request the `sftp` subsystem on an already-open russh session channel and
/// return a ready-to-use async SFTP client over it.
///
/// The channel must have been obtained from a session you opened yourself,
/// e.g. via `session.channel_open_session().await?`.
pub async fn from_channel(channel: Channel<Msg>) -> std::io::Result<RusshSftpClient> {
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| std::io::Error::other(format!("sftp subsystem request failed: {:?}", e)))?;
    from_subsystem_channel(channel).await
}

/// Wrap a russh channel on which the `sftp` subsystem has already been
/// requested. Use this if you manage the subsystem request yourself (for
/// example to pass custom environment or to negotiate a non-standard
/// subsystem name).
pub async fn from_subsystem_channel(channel: Channel<Msg>) -> std::io::Result<RusshSftpClient> {
    let stream = channel.into_stream();
    let (reader, writer) = tokio::io::split(stream);
    AsyncSftpClient::new(reader, writer).await
}
