use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use sftp::{Attributes, Error as SftpError, OpenOptions, SftpClient};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A bidirectional channel backed by the stdin/stdout of an `ssh` subprocess.
struct SshChannel {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl SshChannel {
    fn spawn(destination: &str) -> std::io::Result<Self> {
        let mut child = Command::new("ssh")
            .arg("-s")
            .arg(destination)
            .arg("sftp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture ssh stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture ssh stdout"))?;
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

impl Read for SshChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Write for SshChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stdin.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin.flush()
    }
}

impl Drop for SshChannel {
    fn drop(&mut self) {
        let _ = self.child.wait();
    }
}

struct Shell {
    client: SftpClient<SshChannel>,
    remote_cwd: String,
}

impl Shell {
    fn new(client: SftpClient<SshChannel>) -> Result<Self, SftpError> {
        let remote_cwd = client.realpath(".", None, None)?;
        Ok(Self { client, remote_cwd })
    }

    fn resolve_remote(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_string()
        } else if self.remote_cwd.ends_with('/') {
            format!("{}{}", self.remote_cwd, path)
        } else {
            format!("{}/{}", self.remote_cwd, path)
        }
    }

    fn cmd_pwd(&self) {
        println!("Remote working directory: {}", self.remote_cwd);
    }

    fn cmd_cd(&mut self, path: Option<&str>) -> Result<(), SftpError> {
        let target = match path {
            Some(p) => self.resolve_remote(p),
            None => "/".to_string(),
        };
        let canonical = self.client.realpath(&target, None, None)?;
        let attrs = self.client.stat(&canonical, None)?;
        if !is_dir(&attrs) {
            return Err(SftpError::NotADirectory(String::new(), canonical));
        }
        self.remote_cwd = canonical;
        Ok(())
    }

    fn cmd_ls(&self, args: &[String]) -> Result<(), SftpError> {
        let (long, target) = parse_ls_args(args);
        let path = match target {
            Some(p) => self.resolve_remote(&p),
            None => self.remote_cwd.clone(),
        };
        let attrs = self.client.stat(&path, None)?;
        let entries: Vec<(String, String, Attributes)> = if is_dir(&attrs) {
            let dir = self.client.opendir(&path)?;
            let mut all = Vec::new();
            loop {
                match self.client.readdir(&dir) {
                    Ok(batch) => all.extend(batch),
                    Err(SftpError::Eof(_, _)) => break,
                    Err(e) => {
                        let _ = self.client.closedir(&dir);
                        return Err(e);
                    }
                }
            }
            self.client.closedir(&dir)?;
            all.sort_by(|a, b| a.0.cmp(&b.0));
            all
        } else {
            let name = Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            vec![(name, format_long(&path, &attrs), attrs)]
        };

        if long {
            for (_, longname, _) in &entries {
                if longname.is_empty() {
                    continue;
                }
                println!("{}", longname);
            }
        } else {
            for (name, _, _) in &entries {
                println!("{}", name);
            }
        }
        Ok(())
    }

    fn cmd_mkdir(&self, path: &str) -> Result<(), SftpError> {
        let target = self.resolve_remote(path);
        self.client.mkdir(&target, &Attributes::new())
    }

    fn cmd_rmdir(&self, path: &str) -> Result<(), SftpError> {
        let target = self.resolve_remote(path);
        self.client.rmdir(&target)
    }

    fn cmd_rm(&self, path: &str) -> Result<(), SftpError> {
        let target = self.resolve_remote(path);
        self.client.remove(&target)
    }

    fn cmd_rename(&self, old: &str, new: &str) -> Result<(), SftpError> {
        let from = self.resolve_remote(old);
        let to = self.resolve_remote(new);
        self.client.rename(&from, &to, None)
    }

    fn cmd_symlink(&self, target: &str, link: &str) -> Result<(), SftpError> {
        let link_path = self.resolve_remote(link);
        self.client.symlink(&link_path, target)
    }

    fn cmd_ln(&self, target: &str, link: &str, symbolic: bool) -> Result<(), SftpError> {
        let link_path = self.resolve_remote(link);
        if symbolic {
            self.client.symlink(&link_path, target)
        } else {
            let target_path = self.resolve_remote(target);
            self.client.hardlink(&link_path, &target_path)
        }
    }

    fn cmd_chmod(&self, mode_str: &str, path: &str) -> Result<(), SftpError> {
        let mode = u32::from_str_radix(mode_str, 8).map_err(|e| {
            SftpError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid mode '{}': {}", mode_str, e),
            ))
        })?;
        let target = self.resolve_remote(path);
        let mut attrs = Attributes::new();
        attrs.permissions = Some(mode);
        self.client.setstat(&target, &attrs)
    }

    fn cmd_stat(&self, path: &str) -> Result<(), SftpError> {
        let target = self.resolve_remote(path);
        let attrs = self.client.stat(&target, None)?;
        print_attrs(&target, &attrs);
        Ok(())
    }

    fn cmd_get(&self, remote: &str, local: Option<&str>) -> Result<(), SftpError> {
        let remote_path = self.resolve_remote(remote);
        let local_path = match local {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from(
                Path::new(&remote_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| remote_path.clone()),
            ),
        };

        let file = self.client.open(
            &remote_path,
            OpenOptions::new().read(true),
            &Attributes::new(),
        )?;
        let result = (|| -> Result<u64, SftpError> {
            let mut out = std::fs::File::create(&local_path)?;
            let mut offset: u64 = 0;
            const CHUNK: u32 = 32 * 1024;
            loop {
                match self.client.pread(&file, offset, CHUNK) {
                    Ok(data) if data.is_empty() => break,
                    Ok(data) => {
                        out.write_all(&data)?;
                        offset += data.len() as u64;
                    }
                    Err(SftpError::Eof(_, _)) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(offset)
        })();
        let _ = self.client.fclose(&file);
        let bytes = result?;
        println!("Fetched {} ({} bytes)", local_path.display(), bytes);
        Ok(())
    }

    fn cmd_put(&self, local: &str, remote: Option<&str>) -> Result<(), SftpError> {
        let local_path = PathBuf::from(local);
        let remote_name = match remote {
            Some(p) => p.to_string(),
            None => local_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    SftpError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot derive remote name from local path",
                    ))
                })?,
        };
        let remote_path = self.resolve_remote(&remote_name);

        let mut input = std::fs::File::open(&local_path)?;
        let file = self.client.open(
            &remote_path,
            OpenOptions::new().write(true).create(true).truncate(true),
            &Attributes::new(),
        )?;
        let result = (|| -> Result<u64, SftpError> {
            let mut offset: u64 = 0;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                self.client.pwrite(&file, offset, &buf[..n])?;
                offset += n as u64;
            }
            Ok(offset)
        })();
        let _ = self.client.fclose(&file);
        let bytes = result?;
        println!("Uploaded {} ({} bytes)", remote_path, bytes);
        Ok(())
    }

    fn cmd_lpwd() -> std::io::Result<()> {
        println!(
            "Local working directory: {}",
            std::env::current_dir()?.display()
        );
        Ok(())
    }

    fn cmd_lcd(path: Option<&str>) -> std::io::Result<()> {
        let target = match path {
            Some(p) => PathBuf::from(p),
            None => dirs_home().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no home directory")
            })?,
        };
        std::env::set_current_dir(&target)?;
        Ok(())
    }

    fn cmd_lls(args: &[String]) -> std::io::Result<()> {
        let dir = args
            .first()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            println!("{}", entry.file_name().to_string_lossy());
        }
        Ok(())
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn is_dir(attrs: &Attributes) -> bool {
    attrs
        .permissions
        .is_some_and(|p| (p & 0o170000) == 0o040000)
}

fn parse_ls_args(args: &[String]) -> (bool, Option<String>) {
    let mut long = false;
    let mut target = None;
    for arg in args {
        if arg == "-l" || arg == "-la" || arg == "-al" {
            long = true;
        } else if arg.starts_with('-') {
            // ignore other flags for now
        } else {
            target = Some(arg.clone());
        }
    }
    (long, target)
}

fn format_long(path: &str, attrs: &Attributes) -> String {
    let perms = attrs
        .permissions
        .map(|p| format!("{:o}", p))
        .unwrap_or_else(|| "?".to_string());
    let size = attrs
        .size
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!("{} {} {}", perms, size, path)
}

fn print_attrs(path: &str, attrs: &Attributes) {
    println!("{}:", path);
    if let Some(s) = attrs.size {
        println!("  size: {}", s);
    }
    if let Some(p) = attrs.permissions {
        println!("  permissions: {:o}", p);
    }
    if let (Some(uid), Some(gid)) = (attrs.uid, attrs.gid) {
        println!("  uid/gid: {}/{}", uid, gid);
    }
    if let (Some(owner), Some(group)) = (attrs.owner.as_deref(), attrs.group.as_deref()) {
        println!("  owner/group: {}/{}", owner, group);
    }
    if let Some((secs, _)) = attrs.modify_time {
        println!("  mtime: {}", secs);
    }
}

fn print_help() {
    println!("Available commands:");
    println!("  cd [path]              change remote directory");
    println!("  pwd                    print remote working directory");
    println!("  ls [-l] [path]         list remote directory");
    println!("  get remote [local]     download file");
    println!("  put local [remote]     upload file");
    println!("  mkdir path             create remote directory");
    println!("  rmdir path             remove remote directory");
    println!("  rm path                remove remote file");
    println!("  rename old new         rename remote file");
    println!("  ln [-s] target link    create hard or symbolic link");
    println!("  symlink target link    create symbolic link");
    println!("  chmod mode path        change permissions (octal)");
    println!("  stat path              show file attributes");
    println!("  lpwd                   print local working directory");
    println!("  lcd [path]             change local directory");
    println!("  lls [path]             list local directory");
    println!("  help, ?                show this help");
    println!("  quit, exit, bye        disconnect");
}

fn dispatch(shell: &mut Shell, line: &str) -> bool {
    let tokens = match shell_words::split(line) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("parse error: {}", e);
            return true;
        }
    };
    if tokens.is_empty() {
        return true;
    }
    let cmd = tokens[0].as_str();
    let args = &tokens[1..];

    let result: Result<(), SftpError> =
        match cmd {
            "quit" | "exit" | "bye" => return false,
            "help" | "?" => {
                print_help();
                Ok(())
            }
            "pwd" => {
                shell.cmd_pwd();
                Ok(())
            }
            "cd" => shell.cmd_cd(args.first().map(String::as_str)),
            "ls" | "dir" => shell.cmd_ls(args),
            "mkdir" => need_arg(args, 1, "mkdir path").and_then(|_| shell.cmd_mkdir(&args[0])),
            "rmdir" => need_arg(args, 1, "rmdir path").and_then(|_| shell.cmd_rmdir(&args[0])),
            "rm" => need_arg(args, 1, "rm path").and_then(|_| shell.cmd_rm(&args[0])),
            "rename" => need_arg(args, 2, "rename old new")
                .and_then(|_| shell.cmd_rename(&args[0], &args[1])),
            "symlink" => need_arg(args, 2, "symlink target link")
                .and_then(|_| shell.cmd_symlink(&args[0], &args[1])),
            "ln" => {
                let symbolic = args.first().map(|s| s == "-s").unwrap_or(false);
                let rest: Vec<&String> = args.iter().filter(|a| a.as_str() != "-s").collect();
                if rest.len() != 2 {
                    Err(usage("ln [-s] target link"))
                } else {
                    shell.cmd_ln(rest[0], rest[1], symbolic)
                }
            }
            "chmod" => need_arg(args, 2, "chmod mode path")
                .and_then(|_| shell.cmd_chmod(&args[0], &args[1])),
            "stat" => need_arg(args, 1, "stat path").and_then(|_| shell.cmd_stat(&args[0])),
            "get" => need_arg(args, 1, "get remote [local]")
                .and_then(|_| shell.cmd_get(&args[0], args.get(1).map(String::as_str))),
            "put" => need_arg(args, 1, "put local [remote]")
                .and_then(|_| shell.cmd_put(&args[0], args.get(1).map(String::as_str))),
            "lpwd" => Shell::cmd_lpwd().map_err(SftpError::Io),
            "lcd" => Shell::cmd_lcd(args.first().map(String::as_str)).map_err(SftpError::Io),
            "lls" => Shell::cmd_lls(args).map_err(SftpError::Io),
            other => {
                eprintln!("unknown command: {} (try 'help')", other);
                Ok(())
            }
        };
    if let Err(e) = result {
        eprintln!("error: {:?}", e);
    }
    true
}

fn need_arg(args: &[String], n: usize, usage_str: &str) -> Result<(), SftpError> {
    if args.len() < n {
        Err(usage(usage_str))
    } else {
        Ok(())
    }
}

fn usage(msg: &str) -> SftpError {
    SftpError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("usage: {}", msg),
    ))
}

fn history_path() -> Option<PathBuf> {
    dirs_home().map(|h| h.join(".sftp_history"))
}

fn main() -> std::io::Result<()> {
    let destination = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: sftp <user@host>");
        std::process::exit(1);
    });

    let channel = SshChannel::spawn(&destination)?;
    let client = SftpClient::new(channel)?;
    println!("Connected. SFTP protocol version: {}", client.version());

    let mut shell = Shell::new(client).map_err(|e| std::io::Error::other(format!("{:?}", e)))?;

    let mut rl =
        DefaultEditor::new().map_err(|e| std::io::Error::other(format!("readline init: {}", e)))?;
    let history = history_path();
    if let Some(h) = &history {
        let _ = rl.load_history(h);
    }

    loop {
        match rl.readline("sftp> ") {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
                if !dispatch(&mut shell, trimmed) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {}", e);
                break;
            }
        }
    }

    if let Some(h) = &history {
        let _ = rl.save_history(h);
    }
    Ok(())
}
