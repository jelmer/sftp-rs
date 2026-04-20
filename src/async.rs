//! Asynchronous SFTP client over a tokio `AsyncRead + AsyncWrite` channel.
//!
//! A single background task owns the read half, demultiplexing responses by
//! request id, so multiple requests can be in flight concurrently on a single
//! connection.

use crate::protocol::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex as TokioMutex};

type Pending = Arc<StdMutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>>;

pub struct AsyncSftpClient<W> {
    writer: TokioMutex<W>,
    pending: Pending,
    last_request_id: AtomicU32,
    version: u32,
    extensions: Vec<(String, String)>,
    reader_task: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<W> Drop for AsyncSftpClient<W> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.reader_task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

async fn read_packet_async<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = i32::from_be_bytes(hdr) as usize;
    if len == 0 {
        return Err(std::io::Error::other("zero-length packet"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let kind = buf[0];
    Ok((kind, buf[1..].to_vec()))
}

async fn write_packet_async<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(5);
    hdr.extend_from_slice(&(body.len() as u32 + 1).to_be_bytes());
    hdr.push(kind);
    w.write_all(&hdr).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

impl<W: AsyncWrite + Unpin + Send + 'static> AsyncSftpClient<W> {
    /// Construct a new async SFTP client by negotiating the protocol over the
    /// given split read/write halves. Spawns a background reader task on the
    /// current tokio runtime.
    pub async fn new<R>(mut reader: R, mut writer: W) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        write_packet_async(&mut writer, SSH_FXP_INIT, &build_init()).await?;
        let (kind, body) = read_packet_async(&mut reader).await?;
        if kind != SSH_FXP_VERSION {
            return Err(std::io::Error::other(format!(
                "Unexpected response to init: {}",
                kind
            )));
        }
        let (version, extensions) = parse_version(&body)?;

        let pending: Pending = Arc::new(StdMutex::new(HashMap::new()));
        let pending_for_task = pending.clone();
        let reader_task = tokio::spawn(async move {
            run_reader(reader, pending_for_task).await;
        });

        Ok(Self {
            writer: TokioMutex::new(writer),
            pending,
            last_request_id: AtomicU32::new(0),
            version,
            extensions,
            reader_task: TokioMutex::new(Some(reader_task)),
        })
    }

    pub fn extensions(&self) -> &[(String, String)] {
        &self.extensions
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    async fn process(&self, cmd: u8, body: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
        let request_id = self.last_request_id.fetch_add(1, Ordering::SeqCst);
        let body = with_request_id(request_id, body);

        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, tx);

        if let Err(e) = {
            let mut guard = self.writer.lock().await;
            write_packet_async(&mut *guard, cmd, &body).await
        } {
            self.pending.lock().unwrap().remove(&request_id);
            return Err(e);
        }

        rx.await
            .map_err(|_| std::io::Error::other("reader task closed before response arrived"))
    }

    pub async fn mkdir(&self, path: &str, attr: &Attributes) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_MKDIR, &build_path_and_attrs(path, attr)?)
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn rmdir(&self, path: &str) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_RMDIR, &build_path_only(path)).await?;
        expect_status(cmd, &data)
    }

    pub async fn readlink(&self, path: &str) -> Result<String> {
        let (cmd, data) = self
            .process(SSH_FXP_READLINK, &build_path_only(path))
            .await?;
        let names = expect_name(cmd, &data)?;
        Ok(names[0].0.clone())
    }

    pub async fn symlink(&self, path: &str, target: &str) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_SYMLINK, &build_two_paths(path, target))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn hardlink(&self, path: &str, target: &str) -> Result<()> {
        self.link(path, target, false).await
    }

    pub async fn link(&self, path: &str, target: &str, symlink: bool) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_LINK, &build_link(path, target, symlink))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn open(&self, path: &str, options: OpenOptions, attr: &Attributes) -> Result<File> {
        let (cmd, data) = self
            .process(SSH_FXP_OPEN, &build_open(path, options.get(), attr)?)
            .await?;
        Ok(File(expect_handle(cmd, &data)?))
    }

    pub async fn realpath(
        &self,
        path: &str,
        control_byte: Option<u8>,
        compose_path: Option<&str>,
    ) -> Result<String> {
        let (cmd, data) = self
            .process(
                SSH_FXP_REALPATH,
                &build_realpath(path, control_byte, compose_path),
            )
            .await?;
        let names = expect_name(cmd, &data)?;
        Ok(names[0].0.clone())
    }

    pub async fn setstat(&self, path: &str, attr: &Attributes) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_SETSTAT, &build_path_and_attrs(path, attr)?)
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn stat(&self, path: &str, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self
            .process(
                SSH_FXP_STAT,
                &build_path_and_flags(path, flags.unwrap_or(0)),
            )
            .await?;
        expect_attrs(cmd, &data)
    }

    pub async fn remove(&self, path: &str) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_REMOVE, &build_path_only(path)).await?;
        expect_status(cmd, &data)
    }

    pub async fn rename(&self, oldpath: &str, newpath: &str, flags: Option<u32>) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_RENAME, &build_rename(oldpath, newpath, flags))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn lstat(&self, path: &str, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self
            .process(
                SSH_FXP_LSTAT,
                &build_path_and_flags(path, flags.unwrap_or(0)),
            )
            .await?;
        expect_attrs(cmd, &data)
    }

    pub async fn opendir(&self, path: &str) -> Result<Directory> {
        let (cmd, data) = self
            .process(SSH_FXP_OPENDIR, &build_path_only(path))
            .await?;
        Ok(Directory(expect_handle(cmd, &data)?))
    }

    pub async fn extended(&self, request: &str, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let (cmd, payload) = self
            .process(SSH_FXP_EXTENDED, &build_extended(request, data))
            .await?;
        expect_extended(cmd, payload)
    }

    pub async fn block(&self, file: &File, offset: u64, length: u64, lockmask: u32) -> Result<()> {
        let (cmd, data) = self
            .process(
                SSH_FXP_BLOCK,
                &build_block(&file.0, offset, length, lockmask),
            )
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn unblock(&self, file: &File, offset: u64, length: u64) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_UNBLOCK, &build_unblock(&file.0, offset, length))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn fsetstat(&self, file: &File, attr: &Attributes) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_FSETSTAT, &build_handle_and_attrs(&file.0, attr)?)
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn fstat(&self, file: &File, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self
            .process(
                SSH_FXP_FSTAT,
                &build_handle_and_flags(&file.0, flags.unwrap_or(0)),
            )
            .await?;
        expect_attrs(cmd, &data)
    }

    pub async fn pwrite(&self, file: &File, offset: u64, data: &[u8]) -> Result<()> {
        let (cmd, payload) = self
            .process(SSH_FXP_WRITE, &build_pwrite(&file.0, offset, data))
            .await?;
        expect_status(cmd, &payload)
    }

    pub async fn pread(&self, file: &File, offset: u64, length: u32) -> Result<Vec<u8>> {
        let (cmd, data) = self
            .process(SSH_FXP_READ, &build_pread(&file.0, offset, length))
            .await?;
        expect_data(cmd, &data)
    }

    pub async fn fclose(&self, file: &File) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_CLOSE, &build_handle_only(&file.0))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn flineseek(&self, file: &File, lineno: u64) -> Result<()> {
        let mut buf = build_handle_only(&file.0);
        buf.extend_from_slice(&lineno.to_be_bytes());
        self.extended("text-seek", buf.as_slice()).await?;
        Ok(())
    }

    pub async fn closedir(&self, dir: &Directory) -> Result<()> {
        let (cmd, data) = self
            .process(SSH_FXP_CLOSE, &build_handle_only(&dir.0))
            .await?;
        expect_status(cmd, &data)
    }

    pub async fn readdir(&self, dir: &Directory) -> Result<Vec<(String, String, Attributes)>> {
        let (cmd, data) = self
            .process(SSH_FXP_READDIR, &build_handle_only(&dir.0))
            .await?;
        expect_readdir(cmd, &data)
    }
}

async fn run_reader<R: AsyncRead + Unpin>(mut reader: R, pending: Pending) {
    loop {
        match read_packet_async(&mut reader).await {
            Ok((cmd, buf)) => {
                let (req_id, payload) = match split_request_id(&buf) {
                    Ok(v) => (v.0, v.1.to_vec()),
                    Err(_) => continue,
                };
                if let Some(tx) = pending.lock().unwrap().remove(&req_id) {
                    let _ = tx.send((cmd, payload));
                }
            }
            Err(_) => {
                // Connection closed or fatal read error; drop all pending senders so
                // their awaits return errors.
                pending.lock().unwrap().clear();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Serve INIT/VERSION then respond to every numbered request with an OK status,
    /// preserving the request id (which lives in the first 4 bytes of the body).
    async fn run_stub_server(mut srv: tokio::io::DuplexStream) {
        // INIT: read its packet
        let (kind, _body) = read_packet_async(&mut srv).await.unwrap();
        assert_eq!(kind, SSH_FXP_INIT);
        // VERSION reply: version=3, no extensions
        let body = 3u32.to_be_bytes().to_vec();
        write_packet_async(&mut srv, SSH_FXP_VERSION, &body)
            .await
            .unwrap();

        // From here on, echo OK status for every request.
        loop {
            match read_packet_async(&mut srv).await {
                Ok((_cmd, body)) => {
                    let req_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&req_id.to_be_bytes());
                    resp.extend_from_slice(&SSH_FX_OK.to_be_bytes());
                    resp.extend_from_slice(&0u32.to_be_bytes());
                    resp.extend_from_slice(&0u32.to_be_bytes());
                    if write_packet_async(&mut srv, SSH_FXP_STATUS, &resp)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    #[tokio::test]
    async fn handshake_and_concurrent_requests() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(run_stub_server(server_io));

        let (cr, cw) = tokio::io::split(client_io);
        let client = AsyncSftpClient::new(cr, cw).await.unwrap();
        assert_eq!(client.version(), 3);

        // Three concurrent requests with distinct ids exercise the demux path.
        let attrs = Attributes::new();
        let (r1, r2, r3) = tokio::join!(
            client.mkdir("/a", &attrs),
            client.mkdir("/b", &attrs),
            client.rmdir("/c"),
        );
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
    }

    #[tokio::test]
    async fn request_fails_after_reader_exits() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (kind, _body) = read_packet_async(&mut server_io).await.unwrap();
            assert_eq!(kind, SSH_FXP_INIT);
            let body = 3u32.to_be_bytes().to_vec();
            write_packet_async(&mut server_io, SSH_FXP_VERSION, &body)
                .await
                .unwrap();
            // Drop the server side so the reader task sees EOF.
        });

        let (cr, cw) = tokio::io::split(client_io);
        let client = AsyncSftpClient::new(cr, cw).await.unwrap();
        let attrs = Attributes::new();
        // The request must not hang after the reader exits.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.mkdir("/x", &attrs),
        )
        .await;
        assert!(result.is_ok(), "request hung after reader closed");
    }

    /// Programmable stub: for each received request, the handler returns
    /// `(response_cmd, response_body_without_request_id)`. The dispatcher re-adds
    /// the request id at the front.
    async fn run_router<F>(mut srv: tokio::io::DuplexStream, mut handler: F)
    where
        F: FnMut(u8, &[u8]) -> (u8, Vec<u8>) + Send,
    {
        let (kind, _body) = read_packet_async(&mut srv).await.unwrap();
        assert_eq!(kind, SSH_FXP_INIT);
        write_packet_async(&mut srv, SSH_FXP_VERSION, &3u32.to_be_bytes())
            .await
            .unwrap();

        loop {
            let (cmd, body) = match read_packet_async(&mut srv).await {
                Ok(p) => p,
                Err(_) => return,
            };
            let (req_id, payload) = split_request_id(&body).unwrap();
            let (resp_cmd, resp_body) = handler(cmd, payload);
            let mut wire = req_id.to_be_bytes().to_vec();
            wire.extend_from_slice(&resp_body);
            if write_packet_async(&mut srv, resp_cmd, &wire).await.is_err() {
                return;
            }
        }
    }

    fn ok_status() -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&SSH_FX_OK.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes()); // empty error message
        body.extend_from_slice(&0u32.to_be_bytes()); // empty lang tag
        (SSH_FXP_STATUS, body)
    }

    fn err_status(code: u32) -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&code.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        (SSH_FXP_STATUS, body)
    }

    fn handle_body(handle: &[u8]) -> (u8, Vec<u8>) {
        let mut body = Vec::with_capacity(4 + handle.len());
        body.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        body.extend_from_slice(handle);
        (SSH_FXP_HANDLE, body)
    }

    fn attrs_body(a: &Attributes) -> (u8, Vec<u8>) {
        (SSH_FXP_ATTRS, a.serialize().unwrap())
    }

    fn data_body(payload: &[u8]) -> (u8, Vec<u8>) {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(payload);
        (SSH_FXP_DATA, body)
    }

    fn name_body(entries: &[(&str, Attributes)]) -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (name, attrs) in entries {
            body.extend_from_slice(&(name.len() as u32).to_be_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&attrs.serialize().unwrap());
        }
        (SSH_FXP_NAME, body)
    }

    fn readdir_body(entries: &[(&str, &str, Attributes)]) -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (name, longname, attrs) in entries {
            body.extend_from_slice(&(name.len() as u32).to_be_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&(longname.len() as u32).to_be_bytes());
            body.extend_from_slice(longname.as_bytes());
            body.extend_from_slice(&attrs.serialize().unwrap());
        }
        (SSH_FXP_NAME, body)
    }

    /// Spin up a client against a stub server that uses `handler`.
    async fn with_stub<F>(
        handler: F,
    ) -> AsyncSftpClient<tokio::io::WriteHalf<tokio::io::DuplexStream>>
    where
        F: FnMut(u8, &[u8]) -> (u8, Vec<u8>) + Send + 'static,
    {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(run_router(server_io, handler));
        let (cr, cw) = tokio::io::split(client_io);
        AsyncSftpClient::new(cr, cw).await.unwrap()
    }

    #[tokio::test]
    async fn async_open_returns_handle() {
        let client = with_stub(|cmd, _body| {
            assert_eq!(cmd, SSH_FXP_OPEN);
            handle_body(b"HANDLE42")
        })
        .await;
        let f = client
            .open("/x", OpenOptions::new().read(true), &Attributes::new())
            .await
            .unwrap();
        assert_eq!(f.0, b"HANDLE42".to_vec());
    }

    #[tokio::test]
    async fn async_open_propagates_no_such_file() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_OPEN);
            err_status(SSH_FX_NO_SUCH_FILE)
        })
        .await;
        match client
            .open(
                "/missing",
                OpenOptions::new().read(true),
                &Attributes::new(),
            )
            .await
        {
            Err(Error::NoSuchFile(_, _)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn async_stat_returns_attributes() {
        let mut a = Attributes::new();
        a.size = Some(1234);
        a.permissions = Some(0o100644);
        let a_clone = a.clone();
        let client = with_stub(move |cmd, _| {
            assert_eq!(cmd, SSH_FXP_STAT);
            attrs_body(&a_clone)
        })
        .await;
        let got = client.stat("/file", None).await.unwrap();
        assert_eq!(got, a);
    }

    #[tokio::test]
    async fn async_lstat_returns_attributes() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_LSTAT);
            attrs_body(&Attributes::new())
        })
        .await;
        client.lstat("/x", None).await.unwrap();
    }

    #[tokio::test]
    async fn async_fstat_returns_attributes() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_FSTAT);
            attrs_body(&Attributes::new())
        })
        .await;
        client.fstat(&File(b"h".to_vec()), None).await.unwrap();
    }

    #[tokio::test]
    async fn async_pread_returns_data() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_READ);
            data_body(b"hello")
        })
        .await;
        let data = client.pread(&File(b"h".to_vec()), 0, 5).await.unwrap();
        assert_eq!(data, b"hello".to_vec());
    }

    #[tokio::test]
    async fn async_pread_propagates_eof() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_READ);
            err_status(SSH_FX_EOF)
        })
        .await;
        match client.pread(&File(b"h".to_vec()), 0, 5).await {
            Err(Error::Eof(_, _)) => {}
            other => panic!("expected Eof, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn async_pwrite_returns_ok() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_WRITE);
            ok_status()
        })
        .await;
        client
            .pwrite(&File(b"h".to_vec()), 0, b"data")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn async_opendir_and_readdir() {
        let client = with_stub(|cmd, _| match cmd {
            SSH_FXP_OPENDIR => handle_body(b"D"),
            SSH_FXP_READDIR => readdir_body(&[
                ("a", "-rw-r--r-- a", Attributes::new()),
                ("b", "-rw-r--r-- b", Attributes::new()),
            ]),
            other => panic!("unexpected cmd {}", other),
        })
        .await;
        let dir = client.opendir("/d").await.unwrap();
        let entries = client.readdir(&dir).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "a");
        assert_eq!(entries[1].0, "b");
    }

    #[tokio::test]
    async fn async_readdir_eof_surfaces() {
        let client = with_stub(|cmd, _| match cmd {
            SSH_FXP_OPENDIR => handle_body(b"D"),
            SSH_FXP_READDIR => err_status(SSH_FX_EOF),
            other => panic!("unexpected cmd {}", other),
        })
        .await;
        let dir = client.opendir("/d").await.unwrap();
        match client.readdir(&dir).await {
            Err(Error::Eof(_, _)) => {}
            other => panic!("expected Eof, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn async_realpath_returns_first_name() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_REALPATH);
            name_body(&[("/home/alice", Attributes::new())])
        })
        .await;
        assert_eq!(
            client.realpath(".", None, None).await.unwrap(),
            "/home/alice"
        );
    }

    #[tokio::test]
    async fn async_readlink_returns_target() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_READLINK);
            name_body(&[("/actual", Attributes::new())])
        })
        .await;
        assert_eq!(client.readlink("/lnk").await.unwrap(), "/actual");
    }

    #[tokio::test]
    async fn async_status_mutators() {
        let client = with_stub(|cmd, _| {
            assert!(matches!(
                cmd,
                SSH_FXP_MKDIR
                    | SSH_FXP_RMDIR
                    | SSH_FXP_REMOVE
                    | SSH_FXP_RENAME
                    | SSH_FXP_SYMLINK
                    | SSH_FXP_LINK
                    | SSH_FXP_SETSTAT
                    | SSH_FXP_FSETSTAT
                    | SSH_FXP_CLOSE
                    | SSH_FXP_BLOCK
                    | SSH_FXP_UNBLOCK
            ));
            ok_status()
        })
        .await;

        let attrs = Attributes::new();
        let handle = File(b"h".to_vec());
        let dir = Directory(b"d".to_vec());

        client.mkdir("/a", &attrs).await.unwrap();
        client.rmdir("/a").await.unwrap();
        client.remove("/a").await.unwrap();
        client.rename("/a", "/b", None).await.unwrap();
        client.symlink("/b", "/a").await.unwrap();
        client.hardlink("/b", "/a").await.unwrap();
        client.setstat("/a", &attrs).await.unwrap();
        client.fsetstat(&handle, &attrs).await.unwrap();
        client.fclose(&handle).await.unwrap();
        client.closedir(&dir).await.unwrap();
        client.block(&handle, 0, 0, 0).await.unwrap();
        client.unblock(&handle, 0, 0).await.unwrap();
    }

    #[tokio::test]
    async fn async_extended_returns_payload_on_reply() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_EXTENDED);
            (SSH_FXP_EXTENDED_REPLY, b"payload".to_vec())
        })
        .await;
        let out = client.extended("x", b"").await.unwrap();
        assert_eq!(out, Some(b"payload".to_vec()));
    }

    #[tokio::test]
    async fn async_extended_returns_none_on_ok_status() {
        let client = with_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_EXTENDED);
            ok_status()
        })
        .await;
        assert_eq!(client.extended("x", b"").await.unwrap(), None);
    }
}
