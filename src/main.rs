#![allow(unused)]

use std::{path::{PathBuf, Path}, io::{ErrorKind, Read, Write}, fs::{File, DirEntry}, time::SystemTime};
use anyhow::{Result, bail};
use indicatif::{ProgressBar, style::ProgressStyle, HumanBytes};

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

    for f in std::fs::read_dir(path)? {
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

fn free_space(path: &Path, ignore_file: Option<&Path>) -> Result<()> {
    if let Some((oldest, size)) = oldest_file(path, ignore_file)? {
        println!("Removing {} ({})", oldest.display(), HumanBytes(size));
        std::fs::remove_file(oldest)?;
        Ok(())
    } else {
        bail!("Cannot free space at {} because there are no other files to remove", path.display())
    }
}

fn copy_file_to_file(source: &Path, dest: &Path, total: u64) -> Result<()> {
    println!("{source:?} -> {dest:?}");

    let mut infile = File::open(source)?;
    let mut outfile = File::create(dest)?;
    let mut buffer = [0_u8; 4];
    let progress = ProgressBar::new(total);
    progress.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{eta_precise}] {binary_bytes_per_sec} {bytes}/{total_bytes} {bar} {percent}% {wide_msg:>!}")?
    );
    
    let message = source.to_string_lossy().to_string();
    progress.set_message(message);
    loop {
        let read = infile.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if let Err(e) = outfile.write_all(&buffer) {
            if e.raw_os_error() == Some(libc::ENOSPC) || e.raw_os_error() == Some(libc::EDQUOT) {
                progress.suspend(|| {
                    free_space(dest.parent().unwrap(), Some(dest))
                })?;
            } else {
                bail!(e);
            }
        }
        progress.inc(read as u64);
    }
    progress.finish();
    Ok(())
}

fn main() {
    use clap::{Command,Arg,arg,command};
    let matches = command!()
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
        .get_matches();
    let source = PathBuf::from(matches.get_one::<String>("source").unwrap().as_str());
    let dest = PathBuf::from(matches.get_one::<String>("dest").unwrap().as_str());

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
                copy_file_to_file(&source, &dest, source_metadata.len()).unwrap();
            } else {
                if let Some(source_filename) = source.file_name() {
                    let dest_filename = dest.join(&source_filename);
                    copy_file_to_file(&source, &dest_filename, source_metadata.len()).unwrap();
                } else {
                    todo!();
                }
            }
        } else { /* Dest does not exist (we consider it the dest filename) */
            copy_file_to_file(&source, &dest, source_metadata.len()).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{PathBuf, Path};

    const TEST_DIR: &str = "/Volumes/WammuTest/";

    #[test]
    fn test_get_oldest() {
        let oldest = oldest_file(
            Path::new(TEST_DIR),
            Some(Path::new("/usr/bin/ptargrep5.30"))).unwrap();
        dbg!(oldest);
    }

}

