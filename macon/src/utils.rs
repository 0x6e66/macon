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

pub fn get_string_from_binary(sample_data: &[u8]) -> String {
    // count number of null bytes in odd positions
    let count = sample_data
        .iter()
        .enumerate()
        .filter(|(i, e)| *i % 2 == 1 && **e == 0)
        .count();
    // if more than 98% percent of odd bytes are null it is probably utf16
    let is_utf16 = (2 * count) as f32 / sample_data.len() as f32 > 0.98;

    // get sample data as string based on utf-8 oder utf-16
    match is_utf16 {
        false => String::from_utf8_lossy(sample_data).to_string(),
        true => {
            let tmp: Vec<u16> = (0..sample_data.len() / 2)
                .map(|i| u16::from_le_bytes([sample_data[2 * i], sample_data[2 * i + 1]]))
                .collect();

            String::from_utf16_lossy(&tmp)
        }
    }
}
