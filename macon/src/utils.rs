use std::io::{Cursor, Read};

use anyhow::{Result, anyhow};
use zip::ZipArchive;

pub fn extract_from_zip(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    sample_filename: &str,
    try_with_removed_encryption_bits: bool,
) -> Result<Vec<u8>> {
    // try to extract file from zip the normal way
    if let Ok(mut zipfile) = archive.by_name(sample_filename) {
        let mut buff = Vec::with_capacity(zipfile.size() as usize);
        zipfile.read_to_end(&mut buff)?;
        return Ok(buff);
    }

    if !try_with_removed_encryption_bits {
        return Err(anyhow!(
            "Falid to extract file '{sample_filename}' from zip archive"
        ));
    }

    // get inner data of archive and remove encryption bits from every file in archive
    let sample_data = archive.clone().into_inner().into_inner();
    let sample_data = macon_zip::try_remove_encryption_bits(sample_data)?;

    // create new archive
    let cursor = Cursor::new(sample_data);
    let mut archive = ZipArchive::new(cursor)?;

    // try to extract file again
    let mut zipfile = archive.by_name(sample_filename)?;
    let mut buff = Vec::with_capacity(zipfile.size() as usize);
    zipfile.read_to_end(&mut buff)?;

    Ok(buff)
}
