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
