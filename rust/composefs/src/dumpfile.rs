//! # Parsing and generating composefs dump file entry
//!
//! The composefs project defines a "dump file" which is a textual
//! serializion of the metadata file.  This module supports parsing
//! and generating dump file entries.
use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Display;
use std::fmt::Write as WriteFmt;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread::JoinHandle;

use anyhow::Context;
use anyhow::{anyhow, Result};
use libc::S_IFDIR;

/// https://github.com/torvalds/linux/blob/47ac09b91befbb6a235ab620c32af719f8208399/include/uapi/linux/limits.h#L15
/// This isn't exposed in libc/rustix, and in any case we should be conservative...if this ever
/// gets bumped it'd be a hazard.
const XATTR_NAME_MAX: usize = 255;
// See above
const XATTR_SIZE_MAX: usize = u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
/// An extended attribute entry
pub struct Xattr<'k> {
    /// key
    pub key: Cow<'k, OsStr>,
    /// value
    pub value: Cow<'k, [u8]>,
}
/// A full set of extended attributes
pub type Xattrs<'k> = Vec<Xattr<'k>>;

/// Modification time
#[derive(Debug, PartialEq, Eq)]
pub struct Mtime {
    /// Seconds
    pub sec: u64,
    /// Nanoseconds
    pub nsec: u64,
}

/// A composefs dumpfile entry
#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'p> {
    /// The filename
    pub path: Cow<'p, Path>,
    /// uid
    pub uid: u32,
    /// gid
    pub gid: u32,
    /// mode (includes file type)
    pub mode: u32,
    /// Modification time
    pub mtime: Mtime,
    /// The specific file/directory data
    pub item: Item<'p>,
    /// Extended attributes
    pub xattrs: Xattrs<'p>,
}

#[derive(Debug, PartialEq, Eq)]
/// A serializable composefs entry.
///
/// The `Display` implementation for this type is defined to serialize
/// into a format consumable by `mkcomposefs --from-file`.
pub enum Item<'p> {
    /// A regular file
    Regular {
        /// Size of the file
        size: u64,
        /// Number of links
        nlink: u32,
        /// Inline content
        inline_content: Option<Cow<'p, [u8]>>,
        /// The fsverity digest
        fsverity_digest: Option<String>,
    },
    /// A character or block device node
    Device {
        /// Number of links
        nlink: u32,
        /// The device number
        rdev: u32,
    },
    /// A symbolic link
    Symlink {
        /// Number of links
        nlink: u32,
        /// Symlink target
        target: Cow<'p, Path>,
    },
    /// A hardlink entry
    Hardlink {
        /// The hardlink target
        target: Cow<'p, Path>,
    },
    /// FIFO
    Fifo {
        /// Number of links
        nlink: u32,
    },
    /// A directory
    Directory {
        /// Size of a directory is not necessarily meaningful
        size: u64,
        /// Number of links
        nlink: u32,
    },
}

/// Unescape a byte array according to the composefs dump file escaping format.
fn unescape(s: &str) -> Result<Cow<[u8]>> {
    // If there are no escapes, just return the input unchanged
    if !s.contains('\\') {
        return Ok(Cow::Borrowed(s.as_bytes()));
    }
    let mut it = s.chars();
    let mut r = Vec::new();
    while let Some(c) = it.next() {
        if c != '\\' {
            write!(r, "{c}").unwrap();
            continue;
        }
        let c = it.next().ok_or_else(|| anyhow!("Unterminated escape"))?;
        let c = match c {
            '\\' => b'\\',
            'n' => b'\n',
            'r' => b'\r',
            't' => b'\t',
            'x' => {
                let mut s = String::new();
                s.push(
                    it.next()
                        .ok_or_else(|| anyhow!("Unterminated hex escape"))?,
                );
                s.push(
                    it.next()
                        .ok_or_else(|| anyhow!("Unterminated hex escape"))?,
                );

                u8::from_str_radix(&s, 16).with_context(|| anyhow!("Invalid hex escape {s}"))?
            }
            o => anyhow::bail!("Invalid escape {o}"),
        };
        r.push(c);
    }
    Ok(r.into())
}

/// Unescape a string into a Rust `OsStr` which is really just an alias for a byte array.
fn unescape_to_osstr(s: &str) -> Result<Cow<OsStr>> {
    let r = match unescape(s)? {
        Cow::Borrowed(v) => Cow::Borrowed(OsStr::from_bytes(v)),
        Cow::Owned(v) => Cow::Owned(OsString::from_vec(v)),
    };
    Ok(r)
}

/// Unescape a string into a Rust `Path` which is really just an alias for a byte array,
/// although there is an implicit assumption that there are no embedded `NUL` bytes.
fn unescape_to_path(s: &str) -> Result<Cow<Path>> {
    let v = unescape_to_osstr(s).and_then(|v| {
        if v.is_empty() {
            anyhow::bail!("Invalid empty path");
        }
        let l = v.len();
        if l > libc::PATH_MAX as usize {
            anyhow::bail!("Path is too long: {l} bytes");
        }
        Ok(v)
    })?;
    let r = match v {
        Cow::Borrowed(v) => Cow::Borrowed(Path::new(v)),
        Cow::Owned(v) => Cow::Owned(PathBuf::from(v)),
    };
    Ok(r)
}

/// Like [`unescape_to_path`], but also ensures the path is in "canonical"
/// form; this has the same semantics as Rust https://doc.rust-lang.org/std/path/struct.Path.html#method.components
/// which in particular removes `.` and extra `//`.
///
/// We also deny uplinks `..` and empty paths.
fn unescape_to_path_canonical(s: &str) -> Result<Cow<Path>> {
    let p = unescape_to_path(s)?;
    let mut components = p.components();
    let mut r = std::path::PathBuf::new();
    let Some(first) = components.next() else {
        anyhow::bail!("Invalid empty path");
    };
    if first != std::path::Component::RootDir {
        anyhow::bail!("Invalid non-absolute path");
    }
    r.push(first);
    for component in components {
        match component {
            // Prefix is a windows thing; I don't think RootDir or CurDir are reachable
            // after the first component has been RootDir.
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::CurDir => {
                anyhow::bail!("Internal error in unescape_to_path_canonical");
            }
            std::path::Component::ParentDir => {
                anyhow::bail!("Invalid \"..\" in path");
            }
            std::path::Component::Normal(_) => {
                r.push(component);
            }
        }
    }
    // If the input was already in normal form,
    // then we can just return the original version, which
    // may itself be a Cow::Borrowed, and hence we free our malloc buffer.
    if r.as_os_str().as_bytes() == p.as_os_str().as_bytes() {
        Ok(p)
    } else {
        // Otherwise return our copy.
        Ok(r.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeMode {
    Standard,
    XattrKey,
}

/// Escape a byte array according to the composefs dump file text format.
fn escape<W: std::fmt::Write>(out: &mut W, s: &[u8], mode: EscapeMode) -> std::fmt::Result {
    // Special case a single `-` as that means "no value".
    if s == b"-" {
        return out.write_str(r"\x2d");
    }
    for c in s.iter().copied() {
        // Escape `=` as hex in xattr keys.
        let is_special = c == b'\\' || (matches!((mode, c), (EscapeMode::XattrKey, b'=')));
        let is_printable = c.is_ascii_alphanumeric() || c.is_ascii_punctuation();
        if is_printable && !is_special {
            out.write_char(c as char)?;
        } else {
            match c {
                b'\\' => out.write_str(r"\\")?,
                b'\n' => out.write_str(r"\n")?,
                b'\t' => out.write_str(r"\t")?,
                b'\r' => out.write_str(r"\r")?,
                o => write!(out, "\\x{:02x}", o)?,
            }
        }
    }
    std::fmt::Result::Ok(())
}

/// If the provided string is empty, map it to `-`.
fn optional_str(s: &str) -> Option<&str> {
    match s {
        "-" => None,
        o => Some(o),
    }
}

impl FromStr for Mtime {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (sec, nsec) = s
            .split_once('.')
            .ok_or_else(|| anyhow!("Missing . in mtime"))?;
        Ok(Self {
            sec: u64::from_str(sec)?,
            nsec: u64::from_str(nsec)?,
        })
    }
}

impl<'k> Xattr<'k> {
    fn parse(s: &'k str) -> Result<Self> {
        let (key, value) = s
            .split_once('=')
            .ok_or_else(|| anyhow!("Missing = in xattrs"))?;
        let key = unescape_to_osstr(key)?;
        let keylen = key.as_bytes().len();
        if keylen > XATTR_NAME_MAX {
            anyhow::bail!(
                "xattr name too long; max={} found={}",
                XATTR_NAME_MAX,
                keylen
            );
        }
        let value = unescape(value)?;
        let valuelen = value.len();
        if valuelen > XATTR_SIZE_MAX {
            anyhow::bail!(
                "xattr value too long; max={} found={}",
                XATTR_SIZE_MAX,
                keylen
            );
        }
        Ok(Self { key, value })
    }
}

impl<'p> Entry<'p> {
    /// Parse an entry from a composefs dump file line.
    pub fn parse(s: &'p str) -> Result<Entry<'p>> {
        let mut components = s.split(' ');
        let mut next = |name: &str| components.next().ok_or_else(|| anyhow!("Missing {name}"));
        let path = unescape_to_path_canonical(next("path")?)?;
        let size = u64::from_str(next("size")?)?;
        let modeval = next("mode")?;
        let (is_hardlink, mode) = if let Some((_, rest)) = modeval.split_once('@') {
            (true, u32::from_str_radix(rest, 8)?)
        } else {
            (false, u32::from_str_radix(modeval, 8)?)
        };
        let nlink = u32::from_str(next("nlink")?)?;
        let uid = u32::from_str(next("uid")?)?;
        let gid = u32::from_str(next("gid")?)?;
        let rdev = u32::from_str(next("rdev")?)?;
        let mtime = Mtime::from_str(next("mtime")?)?;
        let payload = optional_str(next("payload")?);
        let content = optional_str(next("content")?);
        let fsverity_digest = optional_str(next("digest")?);
        let xattrs = components.map(Xattr::parse).collect::<Result<Vec<_>>>()?;

        let ty = libc::S_IFMT & mode;
        let item = if is_hardlink {
            if ty == S_IFDIR {
                anyhow::bail!("Invalid hardlinked directory");
            }
            let target =
                unescape_to_path_canonical(payload.ok_or_else(|| anyhow!("Missing payload"))?)?;
            Item::Hardlink { target }
        } else {
            match ty {
                libc::S_IFREG => Item::Regular {
                    size,
                    nlink,
                    inline_content: content.map(unescape).transpose()?,
                    fsverity_digest: fsverity_digest.map(ToOwned::to_owned),
                },
                libc::S_IFLNK => {
                    // Note that the target of *symlinks* is not required to be in canonical form,
                    // as we don't actually traverse those links on our own, and we need to support
                    // symlinks that e.g. contain `//` or other things.
                    let target =
                        unescape_to_path(payload.ok_or_else(|| anyhow!("Missing payload"))?)?;
                    let targetlen = target.as_os_str().as_bytes().len();
                    if targetlen > libc::PATH_MAX as usize {
                        anyhow::bail!("Target length too large {}", targetlen);
                    }
                    Item::Symlink { nlink, target }
                }
                libc::S_IFIFO => Item::Fifo { nlink },
                libc::S_IFCHR | libc::S_IFBLK => Item::Device { nlink, rdev },
                libc::S_IFDIR => Item::Directory { size, nlink },
                o => {
                    anyhow::bail!("Unhandled mode {o:o}")
                }
            }
        };
        Ok(Entry {
            path,
            uid,
            gid,
            mode,
            mtime,
            item,
            xattrs,
        })
    }

    /// Remove internal entries
    /// FIXME: This is arguably a composefs-info dump bug?
    pub fn filter_special(mut self) -> Self {
        self.xattrs.retain(|v| {
            !matches!(
                (v.key.as_bytes(), &*v.value),
                (b"trusted.overlay.opaque" | b"user.overlay.opaque", b"x")
            )
        });
        self
    }
}

impl<'p> Item<'p> {
    pub(crate) fn size(&self) -> u64 {
        match self {
            Item::Regular { size, .. } | Item::Directory { size, .. } => *size,
            _ => 0,
        }
    }

    pub(crate) fn nlink(&self) -> u32 {
        match self {
            Item::Regular { nlink, .. } => *nlink,
            Item::Device { nlink, .. } => *nlink,
            Item::Symlink { nlink, .. } => *nlink,
            Item::Directory { nlink, .. } => *nlink,
            Item::Fifo { nlink, .. } => *nlink,
            _ => 0,
        }
    }

    pub(crate) fn rdev(&self) -> u32 {
        match self {
            Item::Device { rdev, .. } => *rdev,
            _ => 0,
        }
    }

    pub(crate) fn payload(&self) -> Option<&Path> {
        match self {
            Item::Symlink { target, .. } => Some(target),
            Item::Hardlink { target } => Some(target),
            _ => None,
        }
    }
}

impl Display for Mtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.sec, self.nsec)
    }
}

impl<'p> Display for Entry<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        escape(f, self.path.as_os_str().as_bytes(), EscapeMode::Standard)?;
        write!(
            f,
            " {} {:o} {} {} {} {} {} ",
            self.item.size(),
            self.mode,
            self.item.nlink(),
            self.uid,
            self.gid,
            self.item.rdev(),
            self.mtime,
        )?;
        if let Some(payload) = self.item.payload() {
            escape(f, payload.as_os_str().as_bytes(), EscapeMode::Standard)?;
            f.write_char(' ')?;
        } else {
            write!(f, "- ")?;
        }
        match &self.item {
            Item::Regular {
                fsverity_digest,
                inline_content,
                ..
            } => {
                if let Some(content) = inline_content {
                    escape(f, content, EscapeMode::Standard)?;
                    f.write_char(' ')?;
                } else {
                    write!(f, "- ")?;
                }
                let fsverity_digest = fsverity_digest.as_deref().unwrap_or("-");
                write!(f, "{fsverity_digest}")?;
            }
            _ => {
                write!(f, "- -")?;
            }
        }
        for xattr in self.xattrs.iter() {
            f.write_char(' ')?;
            escape(f, xattr.key.as_bytes(), EscapeMode::XattrKey)?;
            f.write_char('=')?;
            escape(f, &xattr.value, EscapeMode::Standard)?;
        }
        std::fmt::Result::Ok(())
    }
}

#[derive(Debug)]
struct DumpFileIteratorInner {
    recv: mpsc::Receiver<Result<Entry<'static>>>,
}

impl Iterator for DumpFileIteratorInner {
    type Item = Result<Entry<'static>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.recv.recv() {
            Ok(r) => Some(r),
            Err(_) => None,
        }
    }
}

/// Iterator over dumpfile entries.
#[derive(Debug)]
pub struct DumpFileIterator {
    proc: Option<std::process::Child>,
    inner: DumpFileIteratorInner,
    input_copier: Option<JoinHandle<Result<()>>>,
    stderr_copier: Option<JoinHandle<Result<Vec<u8>>>>,
    output_copier: Option<JoinHandle<mpsc::SyncSender<Result<Entry<'static>>>>>,
}

impl Iterator for DumpFileIterator {
    type Item = Result<Entry<'static>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(v) = self.inner.next() {
            return Some(v);
        }
        self.finish();
        None
    }
}

impl DumpFileIterator {
    fn finish(&mut self) {
        let Some(mut proc) = self.proc.take() else {
            // This should only happen if next() is invoked more than once
            return;
        };
        let r = proc.wait();
        // Ensure that all other values are sent
        let Some(output_copier) = self.output_copier.take() else {
            return;
        };
        let Some(stderr_copier) = self.stderr_copier.take() else {
            return;
        };
        let sender = output_copier.join().unwrap();
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                let _ = sender.send(Err(e.into()));
                return;
            }
        };
        let stderr = stderr_copier.join().unwrap();
        if r.success() {
            return;
        }
        let stderr = match stderr {
            Ok(r) => r,
            Err(e) => {
                let _ = sender.send(Err(e.into()));
                return;
            }
        };
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.trim();
        let _ = sender.send(Err(anyhow::anyhow!("composefs-info dump failed: {r}: {stderr}")));
    }
}

/// Configuration for parsing a dumpfile
#[derive(Debug)]
pub struct DumpConfig<'a> {
    /// Only dump these toplevel filenames
    pub filters: Option<&'a [&'a str]>,
}

/// Parse the provided composefs into dumpfile entries.
pub fn dump(input: impl Read + Send + 'static, config: DumpConfig) -> Result<DumpFileIterator> {
    let mut input = std::io::BufReader::new(input);
    let mut proc = Command::new("composefs-info");
    proc.args(["-", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut proc = proc.spawn().context("Spawning composefs-info")?;

    // Buffering is a good idea in general to avoid unbounded memory allocations
    let (send, recv) = std::sync::mpsc::sync_channel(5);

    // SAFETY: we set up stdin
    let mut child_stdin = std::io::BufWriter::new(proc.stdin.take().unwrap());
    let mut child_stdout = std::io::BufReader::new(proc.stdout.take().unwrap());
    let mut child_stderr = std::io::BufReader::new(proc.stderr.take().unwrap());

    let input_copier = std::thread::spawn(move || -> anyhow::Result<()> {
        std::io::copy(&mut input, &mut child_stdin)?;
        Ok(())
    });
    let stderr_copier = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::copy(&mut child_stderr, &mut buf)?;
        Ok(buf)
    });
    let output_copier = std::thread::spawn(move || {
        for line in child_stdout.lines() {
            let line = match line {
                Ok(r) => r,
                Err(e) => {
                    let _ = send.send(Err(e.into()));
                    return send;
                }
            };
            let entry = Entry::parse(&line);
        }
        send
    });
    let inner = DumpFileIteratorInner {
        recv,
    };
    let mut r = DumpFileIterator {
        proc: Some(proc),
        inner,
        input_copier: Some(input_copier),
        stderr_copier: Some(stderr_copier),
        output_copier: Some(output_copier),
    };
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIALS: &[&str] = &["", "foo=bar=baz", r"\x01\x02", "-"];
    const UNQUOTED: &[&str] = &["foo!bar", "hello-world", "--"];

    #[test]
    fn test_escape_roundtrip() {
        let cases = SPECIALS.iter().chain(UNQUOTED);
        for case in cases {
            let mut buf = String::new();
            escape(&mut buf, case.as_bytes(), EscapeMode::Standard).unwrap();
            let case2 = unescape(&buf).unwrap();
            assert_eq!(case, &String::from_utf8(case2.into()).unwrap());
        }
    }

    #[test]
    fn test_escape_unquoted() {
        let cases = UNQUOTED;
        for case in cases {
            let mut buf = String::new();
            escape(&mut buf, case.as_bytes(), EscapeMode::Standard).unwrap();
            assert_eq!(case, &buf);
        }
    }

    #[test]
    fn test_escape_quoted() {
        // We don't escape `=` in standard mode
        {
            let mut buf = String::new();
            escape(&mut buf, b"=", EscapeMode::Standard).unwrap();
            assert_eq!(buf, "=");
        }
        // Verify other special cases
        let cases = &[("=", r"\x3d"), ("-", r"\x2d")];
        for (src, expected) in cases {
            let mut buf = String::new();
            escape(&mut buf, src.as_bytes(), EscapeMode::XattrKey).unwrap();
            assert_eq!(expected, &buf);
        }
    }

    #[test]
    fn test_unescape_path() {
        assert!(unescape_to_path("").is_err());
        let mut p = std::iter::repeat('a')
            .take(libc::PATH_MAX.try_into().unwrap())
            .collect::<String>();
        assert!(unescape_to_path(&p).is_ok());
        p.push('a');
        assert!(unescape_to_path(&p).is_err());
    }

    #[test]
    fn test_unescape_path_canonical() {
        // Invalid cases
        assert!(unescape_to_path_canonical("").is_err());
        assert!(unescape_to_path_canonical("foo").is_err());
        assert!(unescape_to_path_canonical("../blah").is_err());
        assert!(unescape_to_path_canonical("/foo/..").is_err());
        assert!(unescape_to_path_canonical("/foo/../blah").is_err());
        // Verify that we return borrowed input where possible
        assert!(matches!(
            unescape_to_path_canonical("/foo").unwrap(),
            Cow::Borrowed(v) if v.to_str() == Some("/foo")
        ));
        // But an escaped version must be owned
        assert!(matches!(
            unescape_to_path_canonical(r#"/\x66oo"#).unwrap(),
            Cow::Owned(v) if v.to_str() == Some("/foo")
        ));
        // Test successful normalization
        assert_eq!(
            unescape_to_path_canonical("///foo/bar//baz")
                .unwrap()
                .to_str()
                .unwrap(),
            "/foo/bar/baz"
        );
        assert_eq!(
            unescape_to_path_canonical("/.").unwrap().to_str().unwrap(),
            "/"
        );
    }

    #[test]
    fn test_parse() {
        const CONTENT: &str = include_str!("../../../tests/assets/special.dump");
        for line in CONTENT.lines() {
            // Test a full round trip by parsing, serialize, parsing again
            let e = Entry::parse(line).unwrap();
            let serialized = e.to_string();
            assert_eq!(line, serialized);
            let e2 = Entry::parse(&serialized).unwrap();
            assert_eq!(e, e2);
        }
    }

    fn parse_all(name: &str, s: &str) -> Result<()> {
        for line in s.lines() {
            if line.is_empty() {
                continue;
            }
            let _: Entry =
                Entry::parse(line).with_context(|| format!("Test case={name:?} line={line:?}"))?;
        }
        Ok(())
    }

    #[test]
    fn test_should_fail() {
        const CASES: &[(&str, &str)] = &[
            (
                "long link",
                include_str!("../../../tests/assets/should-fail-long-link.dump"),
            ),
            (
                "no ftype",
                include_str!("../../../tests/assets/should-fail-no-ftype.dump"),
            ),
            (
                "long xattr key",
                include_str!("../../../tests/assets/should-fail-long-xattr-key.dump"),
            ),
            (
                "long xattr value",
                include_str!("../../../tests/assets/should-fail-long-xattr-value.dump"),
            ),
            (
                "dir hardlink",
                include_str!("../../../tests/assets/should-fail-dir-hardlink.dump"),
            ),
        ];
        for (name, case) in CASES.iter().copied() {
            assert!(
                parse_all(name, case).is_err(),
                "Expected case {name} to fail"
            );
        }
    }
}
