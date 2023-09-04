#![allow(unused)]

use std::{fs, path::{PathBuf, Path}, io::{ErrorKind, Read, Write}, fs::{File, DirEntry}, time::SystemTime, ffi::CString, os::unix::prelude::MetadataExt};
use anyhow::{Result, bail};
use clap::ArgAction;
use indicatif::{ProgressBar, style::ProgressStyle, HumanBytes};
use filetime::FileTime;

const FLAG_SAFE: u32            = (1 << 0);
const FLAG_PRESERVE_PERMS: u32  = (1 << 1);
const FLAG_PRESERVE_OWNER: u32  = (1 << 2);
const FLAG_PRESERVE_GROUP: u32  = (1 << 3);
const FLAG_PRESERVE_MTIME: u32  = (1 << 4);
const FLAG_ARCHIVE: u32 = 
    FLAG_PRESERVE_PERMS |
    FLAG_PRESERVE_OWNER |
    FLAG_PRESERVE_GROUP |
    FLAG_PRESERVE_MTIME;
const FLAG_CHECK: u32 = (1 << 5);

const FLAGS: [(char, &str, u32, &str); 7] = [
    ('s', "safe", FLAG_SAFE, "Do not delete any files"),
    ('a', "archive", FLAG_ARCHIVE, "Equivalent to -pogt"),
    ('p', "perms", FLAG_PRESERVE_PERMS, "Preserve permissions"),
    ('o', "owner", FLAG_PRESERVE_OWNER, "Preserve owners"),
    ('g', "group", FLAG_PRESERVE_GROUP, "Preserve groups"),
    ('t', "times", FLAG_PRESERVE_MTIME, "Preserve modification times"),
    ('c', "check", FLAG_CHECK, "Compare files after copy"),
];

fn file_info(entry: &DirEntry) -> Result<(bool, SystemTime, u64)> {
    let metadata = entry.metadata()?;
    let is_file = entry.file_type()?.is_file();
    let ctime = metadata.modified()?;
    let size = metadata.len();
    Ok((is_file, ctime, size))
}

fn oldest_file(path: &Path, ignore_file: Option<&Path>) -> Result<Option<(PathBuf,u64)>> {
    let ignore_file = match ignore_file {
        None => None,
        Some(ignore_file) => Some(ignore_file.canonicalize()?)
    };

    /* timestamp, path, size */
    let mut oldest = None::<(SystemTime,PathBuf,u64)>;

    for f in fs::read_dir(path)? {
        let entry = f?;
        if let Ok((is_file, ctime, size)) = file_info(&entry) {
            if is_file && (ignore_file.is_none() || &entry.path() != ignore_file.as_ref().unwrap()) {
                if let Some(oldest_file) = oldest.as_ref() {
                    if ctime < oldest_file.0 {
                        oldest = Some((ctime, entry.path(), size));
                    }
                } else {
                    oldest = Some((ctime, entry.path(), size));
                }
            }
        }
    }

    Ok(oldest.map(|(ctime,path,size)| (path,size)))
}

fn free_space(path: &Path, ignore_file: Option<&Path>, flags: u32) -> Result<()> {
    if let Some((oldest, size)) = oldest_file(path, ignore_file)? {
        if (flags & FLAG_SAFE) == 0 {
            println!("Removing {} ({})", oldest.display(), HumanBytes(size));
            fs::remove_file(oldest)?;
        } else {
            println!("Please remove {} ({}) and try again", oldest.display(), HumanBytes(size));
        }
        Ok(())
    } else {
        bail!("Cannot free space at {} because there are no other files to remove", path.display())
    }
}

fn check(source: &Path, dest: &Path, total: u64, blocksize: usize) -> Result<()> {
    println!("Checking {dest:?}");

    if dest.metadata()?.len() != total {
        bail!("File size mismatch");
    }

    let progress = ProgressBar::new(total);
    progress.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{eta_precise}] {binary_bytes_per_sec} {bytes}/{total_bytes} {bar} {percent}% {wide_msg:>!}")?
    );

    let mut srcbuf: Vec<u8> = Vec::with_capacity(blocksize as usize);
    srcbuf.resize(blocksize, 0);

    let mut dstbuf: Vec<u8> = Vec::with_capacity(blocksize as usize);
    dstbuf.resize(blocksize, 0);

    let mut src = File::open(source)?;
    let mut dst = File::open(dest)?;
    let mut total_remaining = total;
    while total_remaining > 0 {
        let read_block = if total_remaining as usize > blocksize { blocksize } else { total_remaining as usize };
        src.read_exact(&mut srcbuf[0..read_block])?;
        dst.read_exact(&mut dstbuf[0..read_block])?;

        if srcbuf[0..read_block] != dstbuf[0..read_block] {
            bail!("Source and dest contents mismatch");
        }
    }
    Ok(())
}

fn copy_file_to_file(source: &Path, dest: &Path, total: u64, blocksize: usize, flags: u32) -> Result<()> {
    println!("{source:?} -> {dest:?}");

    let parent_dir = dest.parent().unwrap();
    let metadata = source.metadata()?;
    let mut infile = File::open(source)?;

    let mut outfile = loop {
        match File::create(dest) {
            Ok(f) => {
                break f;
            },
            Err(e) => {
                if e.raw_os_error() == Some(libc::ENOSPC) || e.raw_os_error() == Some(libc::EDQUOT) {
                    free_space(parent_dir, None, flags)?;
                    if (flags & FLAG_SAFE) != 0 {
                        return Ok(());
                    }
                } else {
                    bail!(e);
                }
            }
        }
    };

    let mut buffer: Vec<u8> = Vec::with_capacity(blocksize);
    buffer.resize(blocksize, 0);

    let progress = ProgressBar::new(total);
    progress.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{eta_precise}] {binary_bytes_per_sec} {bytes}/{total_bytes} {bar} {percent}% {wide_msg:>!}")?
    );
    
    let message = source.to_string_lossy().to_string();
    progress.set_message(message);
    loop {
        let mut buf_offset = 0;
        let mut remaining = infile.read(&mut buffer)?;
        if remaining == 0 {
            break;
        }

        while remaining > 0 {
            match outfile.write(&buffer[buf_offset..]) {
                Ok(w) => {
                    progress.inc(w as u64);
                    remaining -= w;
                    buf_offset += w;
                },
                Err(e) => {
                    /* EDQUOT: Disk quota exceeded */
                    if e.raw_os_error() == Some(libc::ENOSPC) || e.raw_os_error() == Some(libc::EDQUOT) {
                        progress.suspend(|| {
                            free_space(dest.parent().unwrap(), Some(dest), flags)
                        })?;
                        if (flags & FLAG_SAFE) != 0 {
                            progress.finish();
                            return Ok(());
                        }
                    } else {
                        println!("Error: {e:?}");
                        bail!(e);
                    }
                }
            }
        }
    }
    progress.finish();
    drop(infile);
    drop(outfile);

    /* Restore perms */
    if (flags & FLAG_PRESERVE_PERMS) != 0 {
        fs::set_permissions(dest, metadata.permissions())?;
    }

    /* Restore owner */
    if ((flags & FLAG_PRESERVE_OWNER) != 0) || ((flags & FLAG_PRESERVE_GROUP) != 0) {
        unsafe {
            use std::os::unix::ffi::OsStrExt;

            let dest_metadata = dest.metadata()?;
            let dest = CString::new(dest.as_os_str().as_bytes())?;

            let uid = if (flags & FLAG_PRESERVE_OWNER) != 0 { metadata.uid() } else { dest_metadata.uid() };
            let gid = if (flags & FLAG_PRESERVE_GROUP) != 0 { metadata.gid() } else { dest_metadata.gid() };
            let ret = libc::chown(dest.as_ptr(), uid, gid);
            if ret == -1 {
                bail!(std::io::Error::last_os_error());
            }
        }
    }

    /* Restore mtime */
    if (flags & FLAG_PRESERVE_MTIME) != 0 {
        filetime::set_file_mtime(dest, FileTime::from_last_modification_time(&metadata))?;
    }

    if (flags & FLAG_CHECK) != 0 {
        return check(source, dest, total, blocksize);
    }

    Ok(())
}

fn main() {
    use clap::{Command,Arg,arg,command};
    let mut command = command!()
        .arg(
            Arg::new("source")
                .required(true)
                .help("Source file/directory")
        )
        .arg(
            Arg::new("dest")
                .required(true)
                .help("Source file/directory")
        )
        .arg(arg!(-b --"block-size" <SIZE> "Block size")
            .default_value("128k")
        );
    for (short, long, flag, desc) in FLAGS.iter() {
        command = command.arg(
            Arg::new(*long)
                .long(*long)
                .short(*short)
                .help(desc)
                .action(ArgAction::SetTrue)
        );
    }
    let matches = command.get_matches();
    let source = PathBuf::from(matches.get_one::<String>("source").unwrap().as_str());
    let dest = PathBuf::from(matches.get_one::<String>("dest").unwrap().as_str());
    let mut flags = 0_u32;
    for (_, id, flag, _) in FLAGS.iter() {
        if matches.get_flag(*id) {
            flags |= flag;
        }
    }

    let mut blocksize = matches.get_one::<String>("block-size").unwrap().as_str();
    let mut blocksize_unit: usize = 1;
    if blocksize.ends_with('k') || blocksize.ends_with('K') {
        blocksize_unit = 1024;
        blocksize = &blocksize[0..blocksize.len()-1];
    } else if blocksize.ends_with('m') || blocksize.ends_with('M') {
        blocksize_unit = 1024 * 1024;
        blocksize = &blocksize[0..blocksize.len()-1];
    } else if blocksize.ends_with('g') || blocksize.ends_with('G') {
        blocksize_unit = 1024 * 1024 * 1024;
        blocksize = &blocksize[0..blocksize.len()-1];
    } else if blocksize.ends_with('t') || blocksize.ends_with('T') {
        blocksize_unit = 1024 * 1024 * 1024 * 1024;
        blocksize = &blocksize[0..blocksize.len()-1];
    }
    let blocksize = if let Ok(blocksize) = usize::from_str_radix(blocksize, 10) {
        blocksize * blocksize_unit
    } else {
        panic!("Invalid blocksize: {:?}", matches.get_one::<String>("blocksize").unwrap().as_str());
    };

    let source_metadata = source.metadata().expect("Failed to get source metadata");
    let dest_metadata = match dest.metadata() {
        Ok(metadata) => Some(metadata),
        Err(e) => {
            if let ErrorKind::NotFound = e.kind() {
                None
            } else {
                panic!("{}", e.to_string());
            }
        }
    };

    if source_metadata.is_dir() {
        todo!();
    } else { /* Source is file */
        if let Some(dest_metadata) = dest_metadata {
            if dest_metadata.is_file() { /* Dest is an existing file, overwrite it */
                copy_file_to_file(&source, &dest, source_metadata.len(), blocksize, flags).unwrap();
            } else {
                if let Some(source_filename) = source.file_name() {
                    let dest_filename = dest.join(&source_filename);
                    copy_file_to_file(&source, &dest_filename, source_metadata.len(), blocksize, flags).unwrap();
                } else {
                    todo!();
                }
            }
        } else { /* Dest does not exist (we consider it the dest filename) */
            copy_file_to_file(&source, &dest, source_metadata.len(), blocksize, flags).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{PathBuf, Path};

    const TEST_DIR: &str = "/usr/bin";

    #[test]
    fn test_get_oldest() {
        let oldest = oldest_file(
            Path::new(TEST_DIR),
            None).unwrap();
        dbg!(oldest);
    }

}

