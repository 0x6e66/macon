mod types;

use anyhow::Result;

use crate::types::ZipArchive;

pub fn try_remove_encryption_bits(data: &[u8]) -> Result<Vec<u8>> {
    let mut ziparchive = ZipArchive::try_from(data)?;

    for zipfile in ziparchive.zip_files.iter_mut() {
        zipfile.local_file_header.general_purpose &= !(1 << 3);
    }

    for cdh in ziparchive.central_directory_headers.iter_mut() {
        cdh.general_purpose &= !(1 << 3);
    }

    Ok(ziparchive.to_bytes())
}
