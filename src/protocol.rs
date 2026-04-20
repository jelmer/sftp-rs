//! Pure SFTP wire-protocol codec: types, request builders, response parsers.
//!
//! No I/O. No transport. Bytes in, bytes out. Shared by the sync and async
//! client implementations.

#![allow(dead_code)]

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    Other(u32, String, String),
    Eof(String, String),
    NoSuchFile(String, String),
    PermissionDenied(String, String),
    Failure(String, String),
    BadMessage(String, String),
    NoConnection(String, String),
    ConnectionLost(String, String),
    OpUnsupported(String, String),
    InvalidHandle(String, String),
    NoSuchPath(String, String),
    FileAlreadyExists(String, String),
    WriteProtect(String, String),
    NoMedia(String, String),
    NoSpaceOnFilesystem(String, String),
    QuotaExceeded(String, String),
    UnknownPrincipal(String, String),
    LockConflict(String, String),
    DirNotEmpty(String, String),
    NotADirectory(String, String),
    InvalidFilename(String, String),
    LinkLoop(String, String),
    CannotDelete(String, String),
    InvalidParameter(String, String),
    FileIsADirectory(String, String),
    ByteRangeLockConflict(String, String),
    ByteRangeLockRefused(String, String),
    DeletePending(String, String),
    FileCorrupt(String, String),
    OwnerInvalid(String, String),
    GroupInvalid(String, String),
    NoMatchingByteRangeLock(String, String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            Error::Eof(_, _) => std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""),
            Error::NoSuchFile(_, m) => std::io::Error::new(std::io::ErrorKind::NotFound, m),
            Error::PermissionDenied(_, m) => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)
            }
            Error::NoConnection(_, m) => std::io::Error::new(std::io::ErrorKind::NotConnected, m),
            Error::ConnectionLost(_, m) => {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, m)
            }
            Error::InvalidHandle(_, m) => std::io::Error::new(std::io::ErrorKind::InvalidInput, m),
            Error::NoSuchPath(_, m) => std::io::Error::new(std::io::ErrorKind::NotFound, m),
            Error::FileAlreadyExists(_, m) => {
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, m)
            }
            Error::WriteProtect(_, m) => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)
            }
            Error::NoMedia(_, m) => std::io::Error::new(std::io::ErrorKind::NotFound, m),
            Error::QuotaExceeded(_, m) => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)
            }
            Error::LockConflict(_, m) => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)
            }
            Error::InvalidFilename(_, m) => {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, m)
            }
            _ => std::io::Error::other(format!("{:?}", err)),
        }
    }
}

pub type Result<R> = std::result::Result<R, Error>;

pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
pub const SSH_FILEXFER_ATTR_ACCESSTIME: u32 = 0x00000008;
pub const SSH_FILEXFER_ATTR_CREATETIME: u32 = 0x00000010;
pub const SSH_FILEXFER_ATTR_MODIFYTIME: u32 = 0x00000020;
pub const SSH_FILEXFER_ATTR_ACL: u32 = 0x00000040;
pub const SSH_FILEXFER_ATTR_OWNERGROUP: u32 = 0x00000080;
pub const SSH_FILEXFER_ATTR_SUBSECOND_TIMES: u32 = 0x00000100;
pub const SSH_FILEXFER_ATTR_BITS: u32 = 0x00000200;
pub const SSH_FILEXFER_ATTR_ALLOCATION_SIZE: u32 = 0x00000400;
pub const SSH_FILEXFER_ATTR_TEXT_HINT: u32 = 0x00000800;
pub const SSH_FILEXFER_ATTR_MIME_TYPE: u32 = 0x00001000;
pub const SSH_FILEXFER_ATTR_LINK_COUNT: u32 = 0x00002000;
pub const SSH_FILEXFER_ATTR_UNTRANSLATED_NAME: u32 = 0x00004000;
pub const SSH_FILEXFER_ATTR_CTIME: u32 = 0x00008000;
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

const SSH_FILEXFER_ATTR_KNOWN_TEXT: u8 = 0x00;
const SSH_FILEXFER_ATTR_GUESSED_TEXT: u8 = 0x01;
const SSH_FILEXFER_ATTR_KNOWN_BINARY: u8 = 0x02;
const SSH_FILEXFER_ATTR_GUESSED_BINARY: u8 = 0x03;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextHint {
    KnownText,
    GuessedText,
    KnownBinary,
    GuessedBinary,
}

impl From<TextHint> for u8 {
    fn from(hint: TextHint) -> Self {
        match hint {
            TextHint::KnownText => SSH_FILEXFER_ATTR_KNOWN_TEXT,
            TextHint::GuessedText => SSH_FILEXFER_ATTR_GUESSED_TEXT,
            TextHint::KnownBinary => SSH_FILEXFER_ATTR_KNOWN_BINARY,
            TextHint::GuessedBinary => SSH_FILEXFER_ATTR_GUESSED_BINARY,
        }
    }
}

impl From<u8> for TextHint {
    fn from(hint: u8) -> Self {
        match hint {
            SSH_FILEXFER_ATTR_KNOWN_TEXT => TextHint::KnownText,
            SSH_FILEXFER_ATTR_GUESSED_TEXT => TextHint::GuessedText,
            SSH_FILEXFER_ATTR_KNOWN_BINARY => TextHint::KnownBinary,
            SSH_FILEXFER_ATTR_GUESSED_BINARY => TextHint::GuessedBinary,
            _ => panic!("Invalid text hint"),
        }
    }
}

pub const SSH_FILEXFER_ATTR_FLAGS_READONLY: u32 = 0x00000001;
pub const SSH_FILEXFER_ATTR_FLAGS_SYSTEM: u32 = 0x00000002;
pub const SSH_FILEXFER_ATTR_FLAGS_HIDDEN: u32 = 0x00000004;
pub const SSH_FILEXFER_ATTR_FLAGS_CASE_INSENSITIVE: u32 = 0x00000008;
pub const SSH_FILEXFER_ATTR_FLAGS_ARCHIVE: u32 = 0x00000010;
pub const SSH_FILEXFER_ATTR_FLAGS_ENCRYPTED: u32 = 0x00000020;
pub const SSH_FILEXFER_ATTR_FLAGS_COMPRESSED: u32 = 0x00000040;
pub const SSH_FILEXFER_ATTR_FLAGS_SPARSE: u32 = 0x00000080;
pub const SSH_FILEXFER_ATTR_FLAGS_APPEND_ONLY: u32 = 0x00000100;
pub const SSH_FILEXFER_ATTR_FLAGS_IMMUTABLE: u32 = 0x00000200;
pub const SSH_FILEXFER_ATTR_FLAGS_SYNC: u32 = 0x00000400;
pub const SSH_FILEXFER_ATTR_FLAGS_TRANSLATION_ERR: u32 = 0x00000800;

const SSH_FILEXFER_TYPE_REGULAR: u8 = 1;
const SSH_FILEXFER_TYPE_DIRECTORY: u8 = 2;
const SSH_FILEXFER_TYPE_SYMLINK: u8 = 3;
const SSH_FILEXFER_TYPE_SPECIAL: u8 = 4;
const SSH_FILEXFER_TYPE_UNKNOWN: u8 = 5;
const SSH_FILEXFER_TYPE_SOCKET: u8 = 6;
const SSH_FILEXFER_TYPE_CHAR_DEVICE: u8 = 7;
const SSH_FILEXFER_TYPE_BLOCK_DEVICE: u8 = 8;
const SSH_FILEXFER_TYPE_FIFO: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    Regular,
    Directory,
    Symlink,
    Special,
    #[default]
    Unknown,
    Socket,
    CharDevice,
    BlockDevice,
    Fifo,
}

impl From<Kind> for u8 {
    fn from(val: Kind) -> Self {
        match val {
            Kind::Regular => SSH_FILEXFER_TYPE_REGULAR,
            Kind::Directory => SSH_FILEXFER_TYPE_DIRECTORY,
            Kind::Symlink => SSH_FILEXFER_TYPE_SYMLINK,
            Kind::Special => SSH_FILEXFER_TYPE_SPECIAL,
            Kind::Unknown => SSH_FILEXFER_TYPE_UNKNOWN,
            Kind::Socket => SSH_FILEXFER_TYPE_SOCKET,
            Kind::CharDevice => SSH_FILEXFER_TYPE_CHAR_DEVICE,
            Kind::BlockDevice => SSH_FILEXFER_TYPE_BLOCK_DEVICE,
            Kind::Fifo => SSH_FILEXFER_TYPE_FIFO,
        }
    }
}

impl From<u8> for Kind {
    fn from(kind: u8) -> Self {
        match kind {
            SSH_FILEXFER_TYPE_REGULAR => Kind::Regular,
            SSH_FILEXFER_TYPE_DIRECTORY => Kind::Directory,
            SSH_FILEXFER_TYPE_SYMLINK => Kind::Symlink,
            SSH_FILEXFER_TYPE_SPECIAL => Kind::Special,
            SSH_FILEXFER_TYPE_UNKNOWN => Kind::Unknown,
            SSH_FILEXFER_TYPE_SOCKET => Kind::Socket,
            SSH_FILEXFER_TYPE_CHAR_DEVICE => Kind::CharDevice,
            SSH_FILEXFER_TYPE_BLOCK_DEVICE => Kind::BlockDevice,
            SSH_FILEXFER_TYPE_FIFO => Kind::Fifo,
            f => panic!("Unknown file type {}", f),
        }
    }
}

pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_FSETSTAT: u8 = 10;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
pub const SSH_FXP_LINK: u8 = 21;
pub const SSH_FXP_BLOCK: u8 = 22;
pub const SSH_FXP_UNBLOCK: u8 = 23;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;
pub const SSH_FXP_EXTENDED: u8 = 200;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
pub const SSH_FX_NO_CONNECTION: u32 = 6;
pub const SSH_FX_CONNECTION_LOST: u32 = 7;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;
pub const SSH_FX_INVALID_HANDLE: u32 = 9;
pub const SSH_FX_NO_SUCH_PATH: u32 = 10;
pub const SSH_FX_FILE_ALREADY_EXISTS: u32 = 11;
pub const SSH_FX_WRITE_PROTECT: u32 = 12;
pub const SSH_FX_NO_MEDIA: u32 = 13;
pub const SSH_FX_NO_SPACE_ON_FILESYSTEM: u32 = 14;
pub const SSH_FX_QUOTA_EXCEEDED: u32 = 15;
pub const SSH_FX_UNKNOWN_PRINCIPAL: u32 = 16;
pub const SSH_FX_LOCK_CONFLICT: u32 = 17;
pub const SSH_FX_DIR_NOT_EMPTY: u32 = 18;
pub const SSH_FX_NOT_A_DIRECTORY: u32 = 19;
pub const SSH_FX_INVALID_FILENAME: u32 = 20;
pub const SSH_FX_LINK_LOOP: u32 = 21;
pub const SSH_FX_CANNOT_DELETE: u32 = 22;
pub const SSH_FX_INVALID_PARAMETER: u32 = 23;
pub const SSH_FX_FILE_IS_A_DIRECTORY: u32 = 24;
pub const SSH_FX_BYTE_RANGE_LOCK_CONFLICT: u32 = 25;
pub const SSH_FX_BYTE_RANGE_LOCK_REFUSED: u32 = 26;
pub const SSH_FX_DELETE_PENDING: u32 = 27;
pub const SSH_FX_FILE_CORRUPT: u32 = 28;
pub const SSH_FX_OWNER_INVALID: u32 = 29;
pub const SSH_FX_GROUP_INVALID: u32 = 30;
pub const SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK: u32 = 31;

pub const SFTP_FLAG_READ: u32 = 0x00000001;
pub const SFTP_FLAG_WRITE: u32 = 0x00000002;
pub const SFTP_FLAG_APPEND: u32 = 0x00000004;
pub const SFTP_FLAG_CREAT: u32 = 0x00000008;
pub const SFTP_FLAG_TRUNC: u32 = 0x00000010;
pub const SFTP_FLAG_EXCL: u32 = 0x00000020;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct OpenOptions(u32);

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions(0)
    }

    pub fn read(mut self, read: bool) -> OpenOptions {
        if read {
            self.0 |= SFTP_FLAG_READ;
        } else {
            self.0 &= !SFTP_FLAG_READ;
        }
        self
    }

    pub fn write(mut self, write: bool) -> OpenOptions {
        if write {
            self.0 |= SFTP_FLAG_WRITE;
        } else {
            self.0 &= !SFTP_FLAG_WRITE;
        }
        self
    }

    pub fn append(mut self, append: bool) -> OpenOptions {
        if append {
            self.0 |= SFTP_FLAG_APPEND;
        } else {
            self.0 &= !SFTP_FLAG_APPEND;
        }
        self
    }

    pub fn create(mut self, create: bool) -> OpenOptions {
        if create {
            self.0 |= SFTP_FLAG_CREAT;
        } else {
            self.0 &= !SFTP_FLAG_CREAT;
        }
        self
    }

    pub fn truncate(mut self, truncate: bool) -> OpenOptions {
        if truncate {
            self.0 |= SFTP_FLAG_TRUNC;
        } else {
            self.0 &= !SFTP_FLAG_TRUNC;
        }
        self
    }

    pub fn excl(mut self, excl: bool) -> OpenOptions {
        if excl {
            self.0 |= SFTP_FLAG_EXCL;
        } else {
            self.0 &= !SFTP_FLAG_EXCL;
        }
        self
    }

    pub fn mode(&mut self, mode: u32) -> &mut OpenOptions {
        self.0 |= mode;
        self
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

pub const SSH_FXF_RENAME_OVERWRITE: u32 = 0x00000001;
pub const SSH_FXF_RENAME_ATOMIC: u32 = 0x00000002;
pub const SSH_FXF_RENAME_NATIVE: u32 = 0x00000004;

pub const SSH_FXF_ACCESS_DISPOSITION: u32 = 0x00000007;
pub const SSH_FXF_CREATE_NEW: u32 = 0x00000000;
pub const SSH_FXF_CREATE_TRUNCATE: u32 = 0x00000001;
pub const SSH_FXF_OPEN_EXISTING: u32 = 0x00000002;
pub const SSH_FXF_OPEN_OR_CREATE: u32 = 0x00000003;
pub const SSH_FXF_TRUNCATE_EXISTING: u32 = 0x00000004;
pub const SSH_FXF_APPEND_DATA: u32 = 0x00000008;
pub const SSH_FXF_APPEND_DATA_ATOMIC: u32 = 0x00000010;
pub const SSH_FXF_TEXT_MODE: u32 = 0x00000020;
pub const SSH_FXF_BLOCK_READ: u32 = 0x00000040;
pub const SSH_FXF_BLOCK_WRITE: u32 = 0x00000080;
pub const SSH_FXF_BLOCK_DELETE: u32 = 0x00000100;
pub const SSH_FXF_BLOCK_ADVISORY: u32 = 0x00000200;
pub const SSH_FXF_NOFOLLOW: u32 = 0x00000400;
pub const SSH_FXF_DELETE_ON_CLOSE: u32 = 0x00000800;
pub const SSH_FXF_ACCESS_AUDIT_ALARM_INFO: u32 = 0x00001000;
pub const SSH_FXF_ACCESS_BACKUP: u32 = 0x00002000;
pub const SSH_FXF_BACKUP_STREAM: u32 = 0x00004000;
pub const SSH_FXF_OVERRIDE_OWNER: u32 = 0x00008000;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Attributes {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub allocation_size: Option<u64>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub permissions: Option<u32>,
    pub access_time: Option<(u64, Option<u32>)>,
    pub create_time: Option<(u64, Option<u32>)>,
    pub modify_time: Option<(u64, Option<u32>)>,
    pub ctime: Option<(u64, Option<u32>)>,
    pub acl: Option<Vec<u8>>,
    pub attrib_bits: Option<u32>,
    pub attrib_bits_valid: Option<u32>,
    pub text_hint: Option<TextHint>,
    pub mime_type: Option<String>,
    pub link_count: Option<u32>,
    pub untranslated_name: Option<Vec<u8>>,
    pub extended: Option<Vec<(String, String)>>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn serialize(&self) -> std::io::Result<Vec<u8>> {
        let mut valid_attribute_flags: u32 = 0;
        let buf = Vec::new();
        let mut writer = Cursor::new(buf);
        writer.write_u32::<BigEndian>(valid_attribute_flags)?;

        if let Some(size) = self.size {
            writer.write_u64::<BigEndian>(size)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_SIZE;
        }
        if let Some(allocation_size) = self.allocation_size {
            writer.write_u64::<BigEndian>(allocation_size)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_ALLOCATION_SIZE;
        }
        if let Some(uid) = self.uid {
            writer.write_u32::<BigEndian>(uid)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_UIDGID;
        }
        if let Some(gid) = self.gid {
            writer.write_u32::<BigEndian>(gid)?;
            assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_UIDGID != 0);
        } else {
            assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_UIDGID == 0);
        }
        if let Some(owner) = self.owner.as_ref() {
            writer.write_u32::<BigEndian>(owner.len() as u32)?;
            writer.write_all(owner.as_bytes())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
        }
        if let Some(group) = self.group.as_ref() {
            writer.write_u32::<BigEndian>(group.len() as u32)?;
            writer.write_all(group.as_bytes())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
        }
        if let Some(permissions) = self.permissions {
            writer.write_u32::<BigEndian>(permissions)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if let Some(access_time) = self.access_time {
            writer.write_u64::<BigEndian>(access_time.0)?;
            if let Some(ns) = access_time.1 {
                writer.write_u32::<BigEndian>(ns)?;
                valid_attribute_flags |= SSH_FILEXFER_ATTR_SUBSECOND_TIMES;
            }
            valid_attribute_flags |= SSH_FILEXFER_ATTR_ACCESSTIME;
        }
        if let Some(create_time) = self.create_time {
            writer.write_u64::<BigEndian>(create_time.0)?;
            if let Some(ns) = create_time.1 {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0);
                writer.write_u32::<BigEndian>(ns)?;
            } else {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES == 0);
            }
            valid_attribute_flags |= SSH_FILEXFER_ATTR_CREATETIME;
        }
        if let Some(modify_time) = self.modify_time {
            writer.write_u64::<BigEndian>(modify_time.0)?;
            if let Some(ns) = modify_time.1 {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0);
                writer.write_u32::<BigEndian>(ns)?;
            } else {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES == 0);
            }
            valid_attribute_flags |= SSH_FILEXFER_ATTR_MODIFYTIME;
        }
        if let Some(ctime) = self.ctime {
            writer.write_u64::<BigEndian>(ctime.0)?;
            if let Some(ns) = ctime.1 {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0);
                writer.write_u32::<BigEndian>(ns)?;
            } else {
                assert!(valid_attribute_flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES == 0);
            }
            valid_attribute_flags |= SSH_FILEXFER_ATTR_CTIME;
        }
        if let Some(acl) = self.acl.as_ref() {
            writer.write_u32::<BigEndian>(acl.len() as u32)?;
            writer.write_all(acl.as_slice())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_ACL;
        }
        if let Some(attrib_bits) = self.attrib_bits {
            writer.write_u32::<BigEndian>(attrib_bits)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_BITS;
        }
        if let Some(attrib_bits_valid) = self.attrib_bits_valid {
            writer.write_u32::<BigEndian>(attrib_bits_valid)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_BITS;
        }
        if let Some(text_hint) = self.text_hint {
            writer.write_u8(text_hint.into())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_TEXT_HINT;
        }
        if let Some(mime_type) = self.mime_type.as_ref() {
            writer.write_u32::<BigEndian>(mime_type.len() as u32)?;
            writer.write_all(mime_type.as_bytes())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_MIME_TYPE;
        }
        if let Some(link_count) = self.link_count {
            writer.write_u32::<BigEndian>(link_count)?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_LINK_COUNT;
        }
        if let Some(untranslated_name) = self.untranslated_name.as_ref() {
            writer.write_u32::<BigEndian>(untranslated_name.len() as u32)?;
            writer.write_all(untranslated_name.as_slice())?;
            valid_attribute_flags |= SSH_FILEXFER_ATTR_UNTRANSLATED_NAME;
        }
        if let Some(extended) = self.extended.as_ref() {
            writer.write_u32::<BigEndian>(extended.len() as u32)?;
            for (key, value) in extended.iter() {
                writer.write_u32::<BigEndian>(key.len() as u32)?;
                writer.write_all(key.as_bytes())?;
                writer.write_u32::<BigEndian>(value.len() as u32)?;
                writer.write_all(value.as_bytes())?;
            }
            valid_attribute_flags |= SSH_FILEXFER_ATTR_EXTENDED;
        }

        writer.seek(SeekFrom::Start(0))?;
        writer.write_u32::<BigEndian>(valid_attribute_flags)?;
        Ok(writer.into_inner())
    }

    pub fn deserialize(reader: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
        let valid = reader.read_u32::<BigEndian>()?;

        let size = if valid & SSH_FILEXFER_ATTR_SIZE != 0 {
            Some(reader.read_u64::<BigEndian>()?)
        } else {
            None
        };
        let (uid, gid) = if valid & SSH_FILEXFER_ATTR_UIDGID != 0 {
            (
                Some(reader.read_u32::<BigEndian>()?),
                Some(reader.read_u32::<BigEndian>()?),
            )
        } else {
            (None, None)
        };
        let allocation_size = if valid & SSH_FILEXFER_ATTR_ALLOCATION_SIZE != 0 {
            Some(reader.read_u64::<BigEndian>()?)
        } else {
            None
        };
        let owner = if valid & SSH_FILEXFER_ATTR_OWNERGROUP != 0 {
            Some(read_string(reader, "owner")?)
        } else {
            None
        };
        let group = if valid & SSH_FILEXFER_ATTR_OWNERGROUP != 0 {
            Some(read_string(reader, "group")?)
        } else {
            None
        };
        let permissions = if valid & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            Some(reader.read_u32::<BigEndian>()?)
        } else {
            None
        };
        let access_time = if valid & SSH_FILEXFER_ATTR_ACCESSTIME != 0 {
            let secs = reader.read_u64::<BigEndian>()?;
            let ns = if valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                Some(reader.read_u32::<BigEndian>()?)
            } else {
                None
            };
            Some((secs, ns))
        } else {
            None
        };
        let create_time = if valid & SSH_FILEXFER_ATTR_CREATETIME != 0 {
            let secs = reader.read_u64::<BigEndian>()?;
            let ns = if valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                Some(reader.read_u32::<BigEndian>()?)
            } else {
                None
            };
            Some((secs, ns))
        } else {
            None
        };
        let modify_time = if valid & SSH_FILEXFER_ATTR_MODIFYTIME != 0 {
            let secs = reader.read_u64::<BigEndian>()?;
            let ns = if valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                Some(reader.read_u32::<BigEndian>()?)
            } else {
                None
            };
            Some((secs, ns))
        } else {
            None
        };
        let ctime = if valid & SSH_FILEXFER_ATTR_CTIME != 0 {
            let secs = reader.read_u64::<BigEndian>()?;
            let ns = if valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                Some(reader.read_u32::<BigEndian>()?)
            } else {
                None
            };
            Some((secs, ns))
        } else {
            None
        };
        let acl = if valid & SSH_FILEXFER_ATTR_ACL != 0 {
            let len = reader.read_u32::<BigEndian>()?;
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf)?;
            Some(buf)
        } else {
            None
        };
        let attrib_bits = if valid & SSH_FILEXFER_ATTR_BITS != 0 {
            Some(reader.read_u32::<BigEndian>()?)
        } else {
            None
        };
        let attrib_bits_valid = if valid & SSH_FILEXFER_ATTR_BITS != 0 {
            Some(reader.read_u32::<BigEndian>()?)
        } else {
            None
        };
        let text_hint = if valid & SSH_FILEXFER_ATTR_TEXT_HINT != 0 {
            Some(reader.read_u8()?)
        } else {
            None
        };
        let mime_type = if valid & SSH_FILEXFER_ATTR_MIME_TYPE != 0 {
            Some(read_string(reader, "mime type")?)
        } else {
            None
        };
        let link_count = if valid & SSH_FILEXFER_ATTR_LINK_COUNT != 0 {
            Some(reader.read_u32::<BigEndian>()?)
        } else {
            None
        };
        let untranslated_name = if valid & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME != 0 {
            let len = reader.read_u32::<BigEndian>()?;
            let mut buf = vec![0; len as usize];
            reader.read_exact(&mut buf)?;
            Some(buf)
        } else {
            None
        };
        let extended = if valid & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let len = reader.read_u32::<BigEndian>()?;
            let mut ext = Vec::with_capacity(len as usize);
            for _ in 0..len {
                let k = read_string(reader, "extended key")?;
                let v = read_string(reader, "extended value")?;
                ext.push((k, v));
            }
            Some(ext)
        } else {
            None
        };

        Ok(Self {
            size,
            uid,
            gid,
            allocation_size,
            owner,
            group,
            permissions,
            access_time,
            create_time,
            modify_time,
            ctime,
            acl,
            attrib_bits,
            attrib_bits_valid,
            text_hint: text_hint.map(|h| h.into()),
            mime_type,
            link_count,
            untranslated_name,
            extended,
        })
    }
}

fn read_string(reader: &mut Cursor<&[u8]>, what: &str) -> std::io::Result<String> {
    let len = reader.read_u32::<BigEndian>()?;
    let mut buf = vec![0; len as usize];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid {}: {}", what, e),
        )
    })
}

#[derive(Debug, Clone)]
pub struct File(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct Directory(pub Vec<u8>);

pub fn build_init() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.write_u32::<BigEndian>(3).unwrap();
    buf
}

pub fn parse_version(body: &[u8]) -> std::io::Result<(u32, Vec<(String, String)>)> {
    let mut reader = Cursor::new(body);
    let version = reader.read_u32::<BigEndian>()?;
    if version != 3 {
        return Err(std::io::Error::other(format!(
            "SFTP version mismatch (expected 3, got: {})",
            version
        )));
    }
    let mut extensions = Vec::new();
    while reader.position() < reader.get_ref().len() as u64 {
        let key = read_string(&mut reader, "extension key")?;
        let value = read_string(&mut reader, "extension value")?;
        extensions.push((key, value));
    }
    Ok((version, extensions))
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.write_u32::<BigEndian>(s.len() as u32).unwrap();
    buf.extend_from_slice(s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.write_u32::<BigEndian>(b.len() as u32).unwrap();
    buf.extend_from_slice(b);
}

/// Build a request body containing only a single path field.
pub fn build_path_only(path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + path.len());
    put_str(&mut buf, path);
    buf
}

pub fn build_handle_only(handle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + handle.len());
    put_bytes(&mut buf, handle);
    buf
}

pub fn build_path_and_attrs(path: &str, attr: &Attributes) -> std::io::Result<Vec<u8>> {
    let attrs = attr.serialize()?;
    let mut buf = Vec::with_capacity(4 + path.len() + attrs.len());
    put_str(&mut buf, path);
    buf.extend_from_slice(&attrs);
    Ok(buf)
}

pub fn build_handle_and_attrs(handle: &[u8], attr: &Attributes) -> std::io::Result<Vec<u8>> {
    let attrs = attr.serialize()?;
    let mut buf = Vec::with_capacity(4 + handle.len() + attrs.len());
    put_bytes(&mut buf, handle);
    buf.extend_from_slice(&attrs);
    Ok(buf)
}

pub fn build_path_and_flags(path: &str, flags: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + path.len());
    put_str(&mut buf, path);
    buf.write_u32::<BigEndian>(flags).unwrap();
    buf
}

pub fn build_handle_and_flags(handle: &[u8], flags: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + handle.len());
    put_bytes(&mut buf, handle);
    buf.write_u32::<BigEndian>(flags).unwrap();
    buf
}

pub fn build_two_paths(a: &str, b: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + a.len() + b.len());
    put_str(&mut buf, a);
    put_str(&mut buf, b);
    buf
}

pub fn build_link(path: &str, target: &str, symlink: bool) -> Vec<u8> {
    let mut buf = build_two_paths(path, target);
    buf.push(if symlink { 1 } else { 0 });
    buf
}

pub fn build_open(path: &str, options: u32, attr: &Attributes) -> std::io::Result<Vec<u8>> {
    let attrs = attr.serialize()?;
    let mut buf = Vec::with_capacity(8 + path.len() + attrs.len());
    put_str(&mut buf, path);
    buf.write_u32::<BigEndian>(options).unwrap();
    buf.extend_from_slice(&attrs);
    Ok(buf)
}

pub fn build_realpath(path: &str, control_byte: Option<u8>, compose: Option<&str>) -> Vec<u8> {
    let mut buf = build_path_only(path);
    if let Some(b) = control_byte {
        buf.push(b);
    }
    if let Some(c) = compose {
        put_str(&mut buf, c);
    }
    buf
}

pub fn build_rename(oldpath: &str, newpath: &str, flags: Option<u32>) -> Vec<u8> {
    let mut buf = build_two_paths(oldpath, newpath);
    buf.write_u32::<BigEndian>(
        flags.unwrap_or(SSH_FXF_RENAME_ATOMIC | SSH_FXF_RENAME_NATIVE | SSH_FXF_RENAME_OVERWRITE),
    )
    .unwrap();
    buf
}

pub fn build_extended(request: &str, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + request.len() + data.len());
    put_str(&mut buf, request);
    buf.extend_from_slice(data);
    buf
}

pub fn build_block(handle: &[u8], offset: u64, length: u64, lockmask: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + handle.len() + 8 + 8 + 4);
    put_bytes(&mut buf, handle);
    buf.write_u64::<BigEndian>(offset).unwrap();
    buf.write_u64::<BigEndian>(length).unwrap();
    buf.write_u32::<BigEndian>(lockmask).unwrap();
    buf
}

pub fn build_unblock(handle: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + handle.len() + 8 + 8);
    put_bytes(&mut buf, handle);
    buf.write_u64::<BigEndian>(offset).unwrap();
    buf.write_u64::<BigEndian>(length).unwrap();
    buf
}

pub fn build_pwrite(handle: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + handle.len() + 8 + 4 + data.len());
    put_bytes(&mut buf, handle);
    buf.write_u64::<BigEndian>(offset).unwrap();
    buf.write_u32::<BigEndian>(data.len() as u32).unwrap();
    buf.extend_from_slice(data);
    buf
}

pub fn build_pread(handle: &[u8], offset: u64, length: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + handle.len() + 8 + 4);
    put_bytes(&mut buf, handle);
    buf.write_u64::<BigEndian>(offset).unwrap();
    buf.write_u32::<BigEndian>(length).unwrap();
    buf
}

pub fn parse_status(respdata: &[u8]) -> Result<()> {
    let mut reader = Cursor::new(respdata);
    let status = reader.read_u32::<BigEndian>()?;
    let err_msg = read_string(&mut reader, "error message")?;
    let lang_tag = read_string(&mut reader, "lang tag")?;
    match status {
        SSH_FX_OK => Ok(()),
        SSH_FX_EOF => Err(Error::Eof(err_msg, lang_tag)),
        SSH_FX_NO_SUCH_FILE => Err(Error::NoSuchFile(err_msg, lang_tag)),
        SSH_FX_PERMISSION_DENIED => Err(Error::PermissionDenied(err_msg, lang_tag)),
        SSH_FX_FAILURE => Err(Error::Failure(err_msg, lang_tag)),
        SSH_FX_BAD_MESSAGE => Err(Error::BadMessage(err_msg, lang_tag)),
        SSH_FX_NO_CONNECTION => Err(Error::NoConnection(err_msg, lang_tag)),
        SSH_FX_CONNECTION_LOST => Err(Error::ConnectionLost(err_msg, lang_tag)),
        SSH_FX_OP_UNSUPPORTED => Err(Error::OpUnsupported(err_msg, lang_tag)),
        SSH_FX_INVALID_HANDLE => Err(Error::InvalidHandle(err_msg, lang_tag)),
        SSH_FX_NO_SUCH_PATH => Err(Error::NoSuchPath(err_msg, lang_tag)),
        SSH_FX_FILE_ALREADY_EXISTS => Err(Error::FileAlreadyExists(err_msg, lang_tag)),
        SSH_FX_WRITE_PROTECT => Err(Error::WriteProtect(err_msg, lang_tag)),
        SSH_FX_NO_MEDIA => Err(Error::NoMedia(err_msg, lang_tag)),
        SSH_FX_NO_SPACE_ON_FILESYSTEM => Err(Error::NoSpaceOnFilesystem(err_msg, lang_tag)),
        SSH_FX_QUOTA_EXCEEDED => Err(Error::QuotaExceeded(err_msg, lang_tag)),
        SSH_FX_UNKNOWN_PRINCIPAL => Err(Error::UnknownPrincipal(err_msg, lang_tag)),
        SSH_FX_LOCK_CONFLICT => Err(Error::LockConflict(err_msg, lang_tag)),
        SSH_FX_DIR_NOT_EMPTY => Err(Error::DirNotEmpty(err_msg, lang_tag)),
        SSH_FX_NOT_A_DIRECTORY => Err(Error::NotADirectory(err_msg, lang_tag)),
        SSH_FX_INVALID_FILENAME => Err(Error::InvalidFilename(err_msg, lang_tag)),
        SSH_FX_LINK_LOOP => Err(Error::LinkLoop(err_msg, lang_tag)),
        SSH_FX_CANNOT_DELETE => Err(Error::CannotDelete(err_msg, lang_tag)),
        SSH_FX_INVALID_PARAMETER => Err(Error::InvalidParameter(err_msg, lang_tag)),
        SSH_FX_FILE_IS_A_DIRECTORY => Err(Error::FileIsADirectory(err_msg, lang_tag)),
        SSH_FX_BYTE_RANGE_LOCK_CONFLICT => Err(Error::ByteRangeLockConflict(err_msg, lang_tag)),
        SSH_FX_BYTE_RANGE_LOCK_REFUSED => Err(Error::ByteRangeLockRefused(err_msg, lang_tag)),
        SSH_FX_DELETE_PENDING => Err(Error::DeletePending(err_msg, lang_tag)),
        SSH_FX_FILE_CORRUPT => Err(Error::FileCorrupt(err_msg, lang_tag)),
        SSH_FX_OWNER_INVALID => Err(Error::OwnerInvalid(err_msg, lang_tag)),
        SSH_FX_GROUP_INVALID => Err(Error::GroupInvalid(err_msg, lang_tag)),
        SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK => {
            Err(Error::NoMatchingByteRangeLock(err_msg, lang_tag))
        }
        _ => Err(Error::Other(status, err_msg, lang_tag)),
    }
}

pub fn parse_handle(respdata: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(respdata);
    let handle_len = reader.read_u32::<BigEndian>()?;
    let mut handle = vec![0u8; handle_len as usize];
    reader.read_exact(&mut handle)?;
    Ok(handle)
}

pub fn parse_data(respdata: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(respdata);
    let len = reader.read_u32::<BigEndian>()?;
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data)?;
    Ok(data)
}

pub fn parse_attrs(respdata: &[u8]) -> Result<Attributes> {
    let mut reader = Cursor::new(respdata);
    Attributes::deserialize(&mut reader).map_err(Error::Io)
}

pub fn parse_name(respdata: &[u8]) -> Result<Vec<(String, Attributes)>> {
    let mut reader = Cursor::new(respdata);
    let count = reader.read_u32::<BigEndian>()?;
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let filename = read_string(&mut reader, "filename")?;
        let attrs = Attributes::deserialize(&mut reader)?;
        files.push((filename, attrs));
    }
    Ok(files)
}

pub fn parse_readdir(respdata: &[u8]) -> Result<Vec<(String, String, Attributes)>> {
    let mut reader = Cursor::new(respdata);
    let count = reader.read_u32::<BigEndian>()?;
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let filename = read_string(&mut reader, "filename")?;
        let longname = read_string(&mut reader, "longname")?;
        let attrs = Attributes::deserialize(&mut reader)?;
        files.push((filename, longname, attrs));
    }
    Ok(files)
}

fn unexpected(cmd: u8) -> Error {
    Error::Io(std::io::Error::other(format!(
        "Unexpected response: {}",
        cmd
    )))
}

pub fn expect_status(cmd: u8, data: &[u8]) -> Result<()> {
    match cmd {
        SSH_FXP_STATUS => parse_status(data),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_handle(cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
    match cmd {
        SSH_FXP_HANDLE => parse_handle(data),
        SSH_FXP_STATUS => parse_status(data).map(|_| unreachable!("OK status in handle position")),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_attrs(cmd: u8, data: &[u8]) -> Result<Attributes> {
    match cmd {
        SSH_FXP_ATTRS => parse_attrs(data),
        SSH_FXP_STATUS => parse_status(data).map(|_| unreachable!()),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_data(cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
    match cmd {
        SSH_FXP_DATA => parse_data(data),
        SSH_FXP_STATUS => parse_status(data).map(|_| unreachable!()),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_name(cmd: u8, data: &[u8]) -> Result<Vec<(String, Attributes)>> {
    match cmd {
        SSH_FXP_NAME => parse_name(data),
        SSH_FXP_STATUS => parse_status(data).map(|_| unreachable!()),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_readdir(cmd: u8, data: &[u8]) -> Result<Vec<(String, String, Attributes)>> {
    match cmd {
        SSH_FXP_NAME => parse_readdir(data),
        SSH_FXP_STATUS => parse_status(data).map(|_| unreachable!()),
        _ => Err(unexpected(cmd)),
    }
}

pub fn expect_extended(cmd: u8, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
    match cmd {
        SSH_FXP_EXTENDED_REPLY => Ok(Some(data)),
        SSH_FXP_STATUS => parse_status(&data).map(|_| None),
        _ => Err(unexpected(cmd)),
    }
}

pub fn read_raw_packet<C: Read>(channel: &mut C) -> std::io::Result<(u8, Vec<u8>)> {
    let mut buf = [0u8; 4];
    channel.read_exact(&mut buf)?;
    let len = i32::from_be_bytes(buf);
    let mut buf = vec![0u8; len as usize];
    channel.read_exact(&mut buf)?;
    let kind = buf[0];
    Ok((kind, buf[1..].to_vec()))
}

pub fn write_raw_packet<C: Write>(channel: &mut C, kind: u8, buf: &[u8]) -> std::io::Result<()> {
    let mut channel = std::io::BufWriter::new(channel);
    channel.write_u32::<BigEndian>(buf.len() as u32 + 1)?;
    channel.write_u8(kind)?;
    channel.write_all(buf)?;
    channel.flush()?;
    Ok(())
}

/// Wrap a request body with the request-id prefix used by all numbered requests.
pub fn with_request_id(request_id: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.write_u32::<BigEndian>(request_id).unwrap();
    buf.extend_from_slice(body);
    buf
}

/// Strip the request-id prefix from a response body. Returns (request_id, payload).
pub fn split_request_id(buf: &[u8]) -> std::io::Result<(u32, &[u8])> {
    if buf.len() < 4 {
        return Err(std::io::Error::other(
            "response too short to contain request id",
        ));
    }
    let request_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Ok((request_id, &buf[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_roundtrip_size_perms() {
        let mut a = Attributes::new();
        a.size = Some(12345);
        a.permissions = Some(0o100644);
        let bytes = a.serialize().unwrap();
        let mut cursor = Cursor::new(bytes.as_slice());
        let b = Attributes::deserialize(&mut cursor).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn attributes_roundtrip_uidgid() {
        let mut a = Attributes::new();
        a.uid = Some(1000);
        a.gid = Some(1000);
        let bytes = a.serialize().unwrap();
        let mut cursor = Cursor::new(bytes.as_slice());
        let b = Attributes::deserialize(&mut cursor).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn build_path_only_layout() {
        let body = build_path_only("hello");
        assert_eq!(body, b"\x00\x00\x00\x05hello".to_vec());
    }

    #[test]
    fn build_two_paths_layout() {
        let body = build_two_paths("a", "bc");
        assert_eq!(body, b"\x00\x00\x00\x01a\x00\x00\x00\x02bc".to_vec());
    }

    #[test]
    fn request_id_roundtrip() {
        let body = b"hello".to_vec();
        let wrapped = with_request_id(0x12345678, &body);
        let (id, rest) = split_request_id(&wrapped).unwrap();
        assert_eq!(id, 0x12345678);
        assert_eq!(rest, body.as_slice());
    }

    #[test]
    fn parse_status_ok() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SSH_FX_OK.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        parse_status(&buf).unwrap();
    }

    #[test]
    fn parse_status_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SSH_FX_EOF.to_be_bytes());
        let msg = b"end";
        buf.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        buf.extend_from_slice(msg);
        buf.extend_from_slice(&0u32.to_be_bytes());
        match parse_status(&buf) {
            Err(Error::Eof(m, _)) => assert_eq!(m, "end"),
            other => panic!("expected Eof, got {:?}", other),
        }
    }
}
