//! Synchronous SFTP client over a `Read + Write` channel.

use crate::protocol::*;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::Mutex;

pub struct SftpClient<C> {
    channel: Mutex<C>,
    last_request_id: std::sync::atomic::AtomicU32,
    version: u32,
    extensions: Vec<(String, String)>,
}

impl SftpClient<std::fs::File> {
    #[cfg(unix)]
    pub fn from_fd(fd: i32) -> std::io::Result<SftpClient<std::fs::File>> {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        SftpClient::new(file)
    }

    #[cfg(windows)]
    pub fn from_handle(handle: RawHandle) -> std::io::Result<SftpClient<std::fs::File>> {
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        SftpClient::new(file)
    }
}

impl<C: Read + Write> SftpClient<C> {
    pub fn new(mut channel: C) -> std::io::Result<Self> {
        write_raw_packet(&mut channel, SSH_FXP_INIT, &build_init())?;
        channel.flush()?;
        let (kind, body) = read_raw_packet(&mut channel)?;
        if kind != SSH_FXP_VERSION {
            return Err(std::io::Error::other(format!(
                "Unexpected response to init: {}",
                kind
            )));
        }
        let (version, extensions) = parse_version(&body)?;
        Ok(Self {
            channel: Mutex::new(channel),
            version,
            extensions,
            last_request_id: std::sync::atomic::AtomicU32::new(0),
        })
    }

    pub fn extensions(&self) -> &[(String, String)] {
        &self.extensions
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    fn process(&self, cmd: u8, body: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
        let request_id = self
            .last_request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = with_request_id(request_id, body);

        write_raw_packet(&mut *self.channel.lock().unwrap(), cmd, body.as_slice())?;
        let (cmd, buf) = read_raw_packet(&mut *self.channel.lock().unwrap())?;
        let (resp_id, payload) = split_request_id(&buf)?;
        assert_eq!(resp_id, request_id);
        Ok((cmd, payload.to_vec()))
    }

    /// Create a new directory.
    pub fn mkdir(&self, path: &str, attr: &Attributes) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_MKDIR, &build_path_and_attrs(path, attr)?)?;
        expect_status(cmd, &data)
    }

    /// Remove a directory.
    pub fn rmdir(&self, path: &str) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_RMDIR, &build_path_only(path))?;
        expect_status(cmd, &data)
    }

    pub fn readlink(&self, path: &str) -> Result<String> {
        let (cmd, data) = self.process(SSH_FXP_READLINK, &build_path_only(path))?;
        let names = expect_name(cmd, &data)?;
        Ok(names[0].0.clone())
    }

    pub fn symlink(&self, path: &str, target: &str) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_SYMLINK, &build_two_paths(path, target))?;
        expect_status(cmd, &data)
    }

    pub fn hardlink(&self, path: &str, target: &str) -> Result<()> {
        self.link(path, target, false)
    }

    pub fn link(&self, path: &str, target: &str, symlink: bool) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_LINK, &build_link(path, target, symlink))?;
        expect_status(cmd, &data)
    }

    pub fn open(&self, path: &str, options: OpenOptions, attr: &Attributes) -> Result<File> {
        let (cmd, data) = self.process(SSH_FXP_OPEN, &build_open(path, options.get(), attr)?)?;
        Ok(File(expect_handle(cmd, &data)?))
    }

    pub fn realpath(
        &self,
        path: &str,
        control_byte: Option<u8>,
        compose_path: Option<&str>,
    ) -> Result<String> {
        let (cmd, data) = self.process(
            SSH_FXP_REALPATH,
            &build_realpath(path, control_byte, compose_path),
        )?;
        let names = expect_name(cmd, &data)?;
        Ok(names[0].0.clone())
    }

    pub fn setstat(&self, path: &str, attr: &Attributes) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_SETSTAT, &build_path_and_attrs(path, attr)?)?;
        expect_status(cmd, &data)
    }

    pub fn stat(&self, path: &str, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self.process(
            SSH_FXP_STAT,
            &build_path_and_flags(path, flags.unwrap_or(0)),
        )?;
        expect_attrs(cmd, &data)
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_REMOVE, &build_path_only(path))?;
        expect_status(cmd, &data)
    }

    pub fn rename(&self, oldpath: &str, newpath: &str, flags: Option<u32>) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_RENAME, &build_rename(oldpath, newpath, flags))?;
        expect_status(cmd, &data)
    }

    pub fn lstat(&self, path: &str, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self.process(
            SSH_FXP_LSTAT,
            &build_path_and_flags(path, flags.unwrap_or(0)),
        )?;
        expect_attrs(cmd, &data)
    }

    pub fn opendir(&self, path: &str) -> Result<Directory> {
        let (cmd, data) = self.process(SSH_FXP_OPENDIR, &build_path_only(path))?;
        Ok(Directory(expect_handle(cmd, &data)?))
    }

    pub fn extended(&self, request: &str, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let (cmd, payload) = self.process(SSH_FXP_EXTENDED, &build_extended(request, data))?;
        expect_extended(cmd, payload)
    }

    pub fn block(&self, file: &File, offset: u64, length: u64, lockmask: u32) -> Result<()> {
        let (cmd, data) = self.process(
            SSH_FXP_BLOCK,
            &build_block(&file.0, offset, length, lockmask),
        )?;
        expect_status(cmd, &data)
    }

    pub fn unblock(&self, file: &File, offset: u64, length: u64) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_UNBLOCK, &build_unblock(&file.0, offset, length))?;
        expect_status(cmd, &data)
    }

    pub fn fsetstat(&self, file: &File, attr: &Attributes) -> Result<()> {
        let (cmd, data) =
            self.process(SSH_FXP_FSETSTAT, &build_handle_and_attrs(&file.0, attr)?)?;
        expect_status(cmd, &data)
    }

    pub fn fstat(&self, file: &File, flags: Option<u32>) -> Result<Attributes> {
        let (cmd, data) = self.process(
            SSH_FXP_FSTAT,
            &build_handle_and_flags(&file.0, flags.unwrap_or(0)),
        )?;
        expect_attrs(cmd, &data)
    }

    pub fn pwrite(&self, file: &File, offset: u64, data: &[u8]) -> Result<()> {
        let (cmd, payload) = self.process(SSH_FXP_WRITE, &build_pwrite(&file.0, offset, data))?;
        expect_status(cmd, &payload)
    }

    pub fn pread(&self, file: &File, offset: u64, length: u32) -> Result<Vec<u8>> {
        let (cmd, data) = self.process(SSH_FXP_READ, &build_pread(&file.0, offset, length))?;
        expect_data(cmd, &data)
    }

    pub fn fclose(&self, file: &File) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_CLOSE, &build_handle_only(&file.0))?;
        expect_status(cmd, &data)
    }

    pub fn flineseek(&self, file: &File, lineno: u64) -> Result<()> {
        use byteorder::{BigEndian, WriteBytesExt};
        let mut buf = build_handle_only(&file.0);
        buf.write_u64::<BigEndian>(lineno)?;
        self.extended("text-seek", buf.as_slice())?;
        Ok(())
    }

    pub fn closedir(&self, dir: &Directory) -> Result<()> {
        let (cmd, data) = self.process(SSH_FXP_CLOSE, &build_handle_only(&dir.0))?;
        expect_status(cmd, &data)
    }

    pub fn readdir(&self, dir: &Directory) -> Result<Vec<(String, String, Attributes)>> {
        let (cmd, data) = self.process(SSH_FXP_READDIR, &build_handle_only(&dir.0))?;
        expect_readdir(cmd, &data)
    }
}

#[cfg(feature = "ssh2")]
impl TryFrom<ssh2::Channel> for SftpClient<ssh2::Channel> {
    type Error = std::io::Error;

    fn try_from(mut channel: ssh2::Channel) -> std::result::Result<Self, Self::Error> {
        channel.subsystem("sftp").map_err(std::io::Error::other)?;
        SftpClient::new(channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        read_raw_packet, split_request_id, write_raw_packet, SSH_FXP_ATTRS, SSH_FXP_CLOSE,
        SSH_FXP_DATA, SSH_FXP_EXTENDED, SSH_FXP_EXTENDED_REPLY, SSH_FXP_FSETSTAT, SSH_FXP_FSTAT,
        SSH_FXP_HANDLE, SSH_FXP_INIT, SSH_FXP_LSTAT, SSH_FXP_MKDIR, SSH_FXP_NAME, SSH_FXP_OPEN,
        SSH_FXP_OPENDIR, SSH_FXP_READ, SSH_FXP_READDIR, SSH_FXP_READLINK, SSH_FXP_REALPATH,
        SSH_FXP_REMOVE, SSH_FXP_RENAME, SSH_FXP_RMDIR, SSH_FXP_SETSTAT, SSH_FXP_STAT,
        SSH_FXP_STATUS, SSH_FXP_SYMLINK, SSH_FXP_VERSION, SSH_FXP_WRITE, SSH_FX_EOF,
        SSH_FX_NO_SUCH_FILE, SSH_FX_OK,
    };
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;

    /// Start a background thread that acts as a stub SFTP server on a loopback
    /// socket. Returns a connected client-side TcpStream plus the server's join
    /// handle. The handler is called with `(cmd, body_without_req_id)` and must
    /// return `(response_cmd, response_body_without_req_id)`.
    fn spawn_stub<F>(mut handler: F) -> (TcpStream, JoinHandle<()>)
    where
        F: FnMut(u8, &[u8]) -> (u8, Vec<u8>) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut srv, _) = listener.accept().unwrap();
            // INIT → VERSION handshake.
            let (kind, _) = read_raw_packet(&mut srv).unwrap();
            assert_eq!(kind, SSH_FXP_INIT);
            write_raw_packet(&mut srv, SSH_FXP_VERSION, &3u32.to_be_bytes()).unwrap();
            loop {
                let (cmd, body) = match read_raw_packet(&mut srv) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let (req_id, payload) = split_request_id(&body).unwrap();
                let (resp_cmd, resp_body) = handler(cmd, payload);
                let mut wire = req_id.to_be_bytes().to_vec();
                wire.extend_from_slice(&resp_body);
                if write_raw_packet(&mut srv, resp_cmd, &wire).is_err() {
                    return;
                }
            }
        });
        let client = TcpStream::connect(addr).unwrap();
        // Disable Nagle so small test packets flush promptly.
        client.set_nodelay(true).unwrap();
        (client, server)
    }

    fn ok_status() -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&SSH_FX_OK.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
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
        for (name, long, attrs) in entries {
            body.extend_from_slice(&(name.len() as u32).to_be_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&(long.len() as u32).to_be_bytes());
            body.extend_from_slice(long.as_bytes());
            body.extend_from_slice(&attrs.serialize().unwrap());
        }
        (SSH_FXP_NAME, body)
    }

    fn client(client_io: TcpStream) -> SftpClient<TcpStream> {
        SftpClient::new(client_io).unwrap()
    }

    #[test]
    fn sync_handshake_reads_version() {
        let (io, srv) = spawn_stub(|_, _| ok_status());
        let c = client(io);
        assert_eq!(c.version(), 3);
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_version_helper() {
        // A handshake where the server also advertises extensions.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut srv, _) = listener.accept().unwrap();
            let (kind, _) = read_raw_packet(&mut srv).unwrap();
            assert_eq!(kind, SSH_FXP_INIT);
            let mut body = 3u32.to_be_bytes().to_vec();
            for (k, v) in [("ext1", "v1"), ("ext2", "v2")] {
                body.extend_from_slice(&(k.len() as u32).to_be_bytes());
                body.extend_from_slice(k.as_bytes());
                body.extend_from_slice(&(v.len() as u32).to_be_bytes());
                body.extend_from_slice(v.as_bytes());
            }
            write_raw_packet(&mut srv, SSH_FXP_VERSION, &body).unwrap();
        });
        let io = TcpStream::connect(addr).unwrap();
        let c = SftpClient::new(io).unwrap();
        assert_eq!(c.version(), 3);
        assert_eq!(c.extensions().len(), 2);
        assert_eq!(c.extensions()[0], ("ext1".to_string(), "v1".to_string()));
        server.join().unwrap();
    }

    #[test]
    fn sync_init_fails_on_wrong_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut srv, _) = listener.accept().unwrap();
            let _ = read_raw_packet(&mut srv);
            // Wrong reply kind.
            let _ = write_raw_packet(&mut srv, SSH_FXP_STATUS, &[]);
        });
        let io = TcpStream::connect(addr).unwrap();
        assert!(SftpClient::new(io).is_err());
    }

    #[test]
    fn sync_open_returns_handle() {
        let (io, srv) = spawn_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_OPEN);
            handle_body(b"HSYNC")
        });
        let c = client(io);
        let f = c
            .open("/x", OpenOptions::new().read(true), &Attributes::new())
            .unwrap();
        assert_eq!(f.0, b"HSYNC".to_vec());
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_open_propagates_no_such_file() {
        let (io, srv) = spawn_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_OPEN);
            err_status(SSH_FX_NO_SUCH_FILE)
        });
        let c = client(io);
        match c.open("/x", OpenOptions::new().read(true), &Attributes::new()) {
            Err(Error::NoSuchFile(_, _)) => {}
            other => panic!("expected NoSuchFile, got {:?}", other),
        }
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_stat_returns_attributes() {
        let mut a = Attributes::new();
        a.size = Some(42);
        let a_clone = a.clone();
        let (io, srv) = spawn_stub(move |cmd, _| {
            assert_eq!(cmd, SSH_FXP_STAT);
            attrs_body(&a_clone)
        });
        let c = client(io);
        assert_eq!(c.stat("/x", None).unwrap(), a);
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_lstat_and_fstat() {
        let (io, srv) = spawn_stub(|cmd, _| match cmd {
            SSH_FXP_LSTAT | SSH_FXP_FSTAT => attrs_body(&Attributes::new()),
            other => panic!("unexpected cmd {}", other),
        });
        let c = client(io);
        c.lstat("/x", None).unwrap();
        c.fstat(&File(b"h".to_vec()), None).unwrap();
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_pread_returns_data() {
        let (io, srv) = spawn_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_READ);
            data_body(b"abcd")
        });
        let c = client(io);
        let data = c.pread(&File(b"h".to_vec()), 0, 4).unwrap();
        assert_eq!(data, b"abcd".to_vec());
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_pread_eof_surfaces() {
        let (io, srv) = spawn_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_READ);
            err_status(SSH_FX_EOF)
        });
        let c = client(io);
        match c.pread(&File(b"h".to_vec()), 0, 4) {
            Err(Error::Eof(_, _)) => {}
            other => panic!("expected Eof, got {:?}", other),
        }
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_pwrite_ok() {
        let (io, srv) = spawn_stub(|cmd, _| {
            assert_eq!(cmd, SSH_FXP_WRITE);
            ok_status()
        });
        let c = client(io);
        c.pwrite(&File(b"h".to_vec()), 0, b"xyz").unwrap();
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_opendir_readdir() {
        let (io, srv) = spawn_stub(|cmd, _| match cmd {
            SSH_FXP_OPENDIR => handle_body(b"D"),
            SSH_FXP_READDIR => readdir_body(&[
                ("a", "-rw-r--r-- a", Attributes::new()),
                ("b", "-rw-r--r-- b", Attributes::new()),
            ]),
            other => panic!("unexpected cmd {}", other),
        });
        let c = client(io);
        let dir = c.opendir("/d").unwrap();
        let entries = c.readdir(&dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "a");
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_realpath_and_readlink() {
        let (io, srv) = spawn_stub(|cmd, _| match cmd {
            SSH_FXP_REALPATH => name_body(&[("/abs", Attributes::new())]),
            SSH_FXP_READLINK => name_body(&[("/tgt", Attributes::new())]),
            other => panic!("unexpected cmd {}", other),
        });
        let c = client(io);
        assert_eq!(c.realpath(".", None, None).unwrap(), "/abs");
        assert_eq!(c.readlink("/l").unwrap(), "/tgt");
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_status_mutators() {
        let (io, srv) = spawn_stub(|cmd, _| match cmd {
            SSH_FXP_MKDIR | SSH_FXP_RMDIR | SSH_FXP_REMOVE | SSH_FXP_RENAME | SSH_FXP_SYMLINK
            | SSH_FXP_SETSTAT | SSH_FXP_FSETSTAT | SSH_FXP_CLOSE => ok_status(),
            other => panic!("unexpected cmd {}", other),
        });
        let c = client(io);
        let attrs = Attributes::new();
        let h = File(b"h".to_vec());
        let d = Directory(b"d".to_vec());
        c.mkdir("/a", &attrs).unwrap();
        c.rmdir("/a").unwrap();
        c.remove("/a").unwrap();
        c.rename("/a", "/b", None).unwrap();
        c.symlink("/b", "/a").unwrap();
        c.setstat("/a", &attrs).unwrap();
        c.fsetstat(&h, &attrs).unwrap();
        c.fclose(&h).unwrap();
        c.closedir(&d).unwrap();
        drop(c);
        let _ = srv.join();
    }

    #[test]
    fn sync_extended_payload_and_none() {
        // Two consecutive extended calls: first with a reply, second with OK
        // status to exercise the `None` branch.
        let mut call = 0;
        let (io, srv) = spawn_stub(move |cmd, _| {
            assert_eq!(cmd, SSH_FXP_EXTENDED);
            call += 1;
            if call == 1 {
                (SSH_FXP_EXTENDED_REPLY, b"P".to_vec())
            } else {
                ok_status()
            }
        });
        let c = client(io);
        assert_eq!(c.extended("x", b"").unwrap(), Some(b"P".to_vec()));
        assert_eq!(c.extended("x", b"").unwrap(), None);
        drop(c);
        let _ = srv.join();
    }
}
