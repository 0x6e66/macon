use anyhow::{Error, Result, anyhow};

#[derive(Debug, Default)]
pub struct ZipArchive<'a> {
    pub zip_files: Vec<ZipFile<'a>>,
    pub central_directory_headers: Vec<CDH<'a>>,
    pub eocd: EOCD<'a>,
}

impl ZipArchive<'_> {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(self) -> Vec<u8> {
        let zipfiles = self
            .zip_files
            .into_iter()
            .flat_map(|zf| zf.to_bytes())
            .collect();

        let cdhs = self
            .central_directory_headers
            .into_iter()
            .flat_map(|zf| zf.to_bytes())
            .collect();

        vec![zipfiles, cdhs, self.eocd.to_bytes()]
            .into_iter()
            .flatten()
            .collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for ZipArchive<'a> {
    type Error = Error;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut ziparchive = ZipArchive::default();

        let eocd = EOCD::try_from(value)?;
        ziparchive.eocd = eocd;

        let start = ziparchive.eocd.central_dir_offset as usize;
        let stop = start + ziparchive.eocd.central_dir_size as usize;

        ziparchive.central_directory_headers = CDH::get_vec_from_bytes(&value[start..stop])?;

        let mut zip_files = vec![];

        for cdh in &ziparchive.central_directory_headers {
            let zipfile = ZipFile::try_from_with_compressed_size(
                &value[cdh.local_header_offset as usize..],
                cdh,
            )?;
            zip_files.push(zipfile);
        }

        ziparchive.zip_files = zip_files;

        Ok(ziparchive)
    }
}

#[derive(Default)]
pub struct ZipFile<'a> {
    pub local_file_header: LocalFileHeader<'a>,
    pub file_data: &'a [u8],
    pub data_discriptor: Option<DataDiscriptor>,
}

impl<'a> ZipFile<'a> {
    #[inline(always)]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        let mut len = self.local_file_header.len();
        len += self.file_data.len();
        if let Some(dd) = &self.data_discriptor {
            len += dd.len();
        }

        len
    }

    pub fn try_from_with_compressed_size(value: &'a [u8], cdh: &CDH) -> Result<Self, Error> {
        let local_file_header = LocalFileHeader::try_from(value)?;

        let start = local_file_header.len();
        let stop = start + cdh.compressed_size as usize;

        let file_data = &value[start..stop];

        let data_discriptor = match local_file_header.general_purpose & (1 << 3) != 0 {
            false => None,
            true => {
                let start = local_file_header.len() + file_data.len();
                let data_discriptor = DataDiscriptor::try_from(&value[start..])?;
                Some(data_discriptor)
            }
        };

        Ok(Self {
            local_file_header,
            file_data,
            data_discriptor,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut tmp = vec![self.local_file_header.to_bytes(), self.file_data.to_vec()];

        if let Some(dd) = &self.data_discriptor {
            tmp.push(dd.to_bytes());
        }

        tmp.into_iter().flatten().collect()
    }
}

impl std::fmt::Debug for ZipFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipFile")
            .field("local_file_header", &self.local_file_header)
            .field("file_data", &"omitted")
            .field("data_discriptor", &self.data_discriptor)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct LocalFileHeader<'a> {
    pub signature: u32,
    pub version_needed_to_extract: u16,
    pub general_purpose: u16,
    pub compression_method: u16,
    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,
    pub crc_32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub extra_field_length: u16,
    pub file_name: &'a str,
    pub extra_field: &'a [u8],
}

impl LocalFileHeader<'_> {
    pub fn len(&self) -> usize {
        30 + self.file_name_length as usize + self.extra_field_length as usize
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.signature.to_le_bytes().to_vec(),
            self.version_needed_to_extract.to_le_bytes().to_vec(),
            self.general_purpose.to_le_bytes().to_vec(),
            self.compression_method.to_le_bytes().to_vec(),
            self.last_mod_file_time.to_le_bytes().to_vec(),
            self.last_mod_file_date.to_le_bytes().to_vec(),
            self.crc_32.to_le_bytes().to_vec(),
            self.compressed_size.to_le_bytes().to_vec(),
            self.uncompressed_size.to_le_bytes().to_vec(),
            self.file_name_length.to_le_bytes().to_vec(),
            self.extra_field_length.to_le_bytes().to_vec(),
            self.file_name.as_bytes().to_vec(),
            self.extra_field.to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for LocalFileHeader<'a> {
    type Error = Error;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let signature = u32::from_le_bytes(value[0..4].try_into()?);
        let version_needed_to_extract = u16::from_le_bytes(value[4..6].try_into()?);
        let general_purpose = u16::from_le_bytes(value[6..8].try_into()?);
        let compression_method = u16::from_le_bytes(value[8..10].try_into()?);
        let last_mod_file_time = u16::from_le_bytes(value[10..12].try_into()?);
        let last_mod_file_date = u16::from_le_bytes(value[12..14].try_into()?);
        let crc_32 = u32::from_le_bytes(value[14..18].try_into()?);
        let compressed_size = u32::from_le_bytes(value[18..22].try_into()?);
        let uncompressed_size = u32::from_le_bytes(value[22..26].try_into()?);
        let file_name_length = u16::from_le_bytes(value[26..28].try_into()?);
        let extra_field_length = u16::from_le_bytes(value[28..30].try_into()?);

        let mut start = 30;
        let mut stop = 30 + file_name_length as usize;
        if stop > value.len() {
            return Err(anyhow!("invalid file_name_length"));
        }
        let file_name = std::str::from_utf8(&value[start..stop])?;

        start += file_name_length as usize;
        stop += extra_field_length as usize;
        if stop > value.len() {
            return Err(anyhow!("invalid extra_field_length"));
        }
        let extra_field = &value[start..stop];

        // check for zip64
        if let Some(zip64) = extra_field.first()
            && *zip64 == 1
        {
            return Err(anyhow!("zip64"));
        }

        Ok(Self {
            signature,
            version_needed_to_extract,
            general_purpose,
            compression_method,
            last_mod_file_time,
            last_mod_file_date,
            crc_32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_name,
            extra_field,
        })
    }
}

#[derive(Debug, Default)]
pub struct DataDiscriptor {
    pub signature: Option<u32>,
    pub crc_32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

impl DataDiscriptor {
    #[inline(always)]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        if self.signature.is_some() { 16 } else { 12 }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut tmp = vec![
            self.crc_32.to_le_bytes().to_vec(),
            self.compressed_size.to_le_bytes().to_vec(),
            self.uncompressed_size.to_le_bytes().to_vec(),
        ];

        if let Some(sig) = self.signature {
            tmp.insert(0, sig.to_le_bytes().to_vec());
        }

        tmp.into_iter().flatten().collect()
    }
}

impl TryFrom<&[u8]> for DataDiscriptor {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let signature = match u32::from_le_bytes(value[0..4].try_into()?) {
            v if v == 0x8074b50 => Some(v),
            _ => None,
        };

        let start = match signature.is_some() {
            true => 4,
            false => 0,
        };

        let crc_32 = u32::from_le_bytes(value[start..start + 4].try_into()?);
        let compressed_size = u32::from_le_bytes(value[start + 4..start + 8].try_into()?);
        let uncompressed_size = u32::from_le_bytes(value[start + 8..start + 12].try_into()?);

        Ok(Self {
            signature,
            crc_32,
            compressed_size,
            uncompressed_size,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default)]
pub struct CDH<'a> {
    /// central file header signature (0x02014b50 (LE))
    pub signature: u32,
    pub version_made_by: u16,
    pub version_needed_to_extract: u16,
    pub general_purpose: u16,
    pub compression_method: u16,
    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,
    pub crc_32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub extra_field_length: u16,
    pub file_comment_length: u16,
    pub disk_number_start: u16,
    pub internal_file_attributes: u16,
    pub external_file_attributes: u32,
    pub local_header_offset: u32,
    pub file_name: &'a str,
    pub extra_field: &'a [u8],
    pub file_comment: &'a [u8],
}

impl<'a> CDH<'a> {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.file_name_length as usize
            + self.extra_field_length as usize
            + self.file_comment_length as usize
            + 46
    }

    pub fn get_vec_from_bytes(value: &'a [u8]) -> Result<Vec<Self>, Error> {
        let mut cdhs = vec![];
        let mut pos = 0;

        while pos < value.len() {
            let cdh = CDH::try_from(&value[pos..])?;
            pos += cdh.len();
            cdhs.push(cdh);
        }
        Ok(cdhs)
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.signature.to_le_bytes().to_vec(),
            self.version_made_by.to_le_bytes().to_vec(),
            self.version_needed_to_extract.to_le_bytes().to_vec(),
            self.general_purpose.to_le_bytes().to_vec(),
            self.compression_method.to_le_bytes().to_vec(),
            self.last_mod_file_time.to_le_bytes().to_vec(),
            self.last_mod_file_date.to_le_bytes().to_vec(),
            self.crc_32.to_le_bytes().to_vec(),
            self.compressed_size.to_le_bytes().to_vec(),
            self.uncompressed_size.to_le_bytes().to_vec(),
            self.file_name_length.to_le_bytes().to_vec(),
            self.extra_field_length.to_le_bytes().to_vec(),
            self.file_comment_length.to_le_bytes().to_vec(),
            self.disk_number_start.to_le_bytes().to_vec(),
            self.internal_file_attributes.to_le_bytes().to_vec(),
            self.external_file_attributes.to_le_bytes().to_vec(),
            self.local_header_offset.to_le_bytes().to_vec(),
            self.file_name.as_bytes().to_vec(),
            self.extra_field.to_vec(),
            self.file_comment.to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for CDH<'a> {
    type Error = Error;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let signature = u32::from_le_bytes(value[0..4].try_into()?);
        let version_made_by = u16::from_le_bytes(value[4..6].try_into()?);
        let version_needed_to_extract = u16::from_le_bytes(value[6..8].try_into()?);
        let general_purpose = u16::from_le_bytes(value[8..10].try_into()?);
        let compression_method = u16::from_le_bytes(value[10..12].try_into()?);
        let last_mod_file_time = u16::from_le_bytes(value[12..14].try_into()?);
        let last_mod_file_date = u16::from_le_bytes(value[14..16].try_into()?);
        let crc_32 = u32::from_le_bytes(value[16..20].try_into()?);
        let compressed_size = u32::from_le_bytes(value[20..24].try_into()?);
        let uncompressed_size = u32::from_le_bytes(value[24..28].try_into()?);
        let file_name_length = u16::from_le_bytes(value[28..30].try_into()?);
        let extra_field_length = u16::from_le_bytes(value[30..32].try_into()?);
        let file_comment_length = u16::from_le_bytes(value[32..34].try_into()?);
        let disk_number_start = u16::from_le_bytes(value[34..36].try_into()?);
        let internal_file_attributes = u16::from_le_bytes(value[36..38].try_into()?);
        let external_file_attributes = u32::from_le_bytes(value[38..42].try_into()?);
        let local_header_offset = u32::from_le_bytes(value[42..46].try_into()?);

        let mut start = 46;
        let mut stop = 46 + file_name_length as usize;
        if stop > value.len() {
            return Err(anyhow!("invalid file_name_length"));
        }
        let file_name = std::str::from_utf8(&value[start..stop])?;

        start += file_name_length as usize;
        stop += extra_field_length as usize;
        if stop > value.len() {
            return Err(anyhow!("invalid extra_field_length"));
        }
        let extra_field = &value[start..stop];

        start += extra_field_length as usize;
        stop += file_comment_length as usize;
        if stop > value.len() {
            return Err(anyhow!("invalid extra_field_length"));
        }
        let file_comment = &value[start..stop];

        Ok(Self {
            signature,
            version_made_by,
            version_needed_to_extract,
            general_purpose,
            compression_method,
            last_mod_file_time,
            last_mod_file_date,
            crc_32,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_comment_length,
            disk_number_start,
            internal_file_attributes,
            external_file_attributes,
            local_header_offset,
            file_name,
            extra_field,
            file_comment,
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default)]
pub struct EOCD<'a> {
    /// end of central directory signature (0x06064b50 (LE))
    pub signature: u32,

    /// number of this disk
    pub disk_number: u16,

    /// number of the disk with the start of the central directory
    pub central_dir_start_disk: u16,

    /// total number of entries in the central dir on this disk
    pub cental_dir_entries_disk: u16,

    /// total number of entries in the central dir
    pub cental_dir_entries_total: u16,

    /// size of the central directory
    pub central_dir_size: u32,

    /// offset of start of central directory with respect to the starting disk number
    pub central_dir_offset: u32,

    /// zipfile comment length
    pub comment_length: u16,

    /// zipfile comment (variable size)
    pub comment: &'a [u8],
}

impl EOCD<'_> {
    #[allow(dead_code)]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.comment_length as usize + 22
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.signature.to_le_bytes().to_vec(),
            self.disk_number.to_le_bytes().to_vec(),
            self.central_dir_start_disk.to_le_bytes().to_vec(),
            self.cental_dir_entries_disk.to_le_bytes().to_vec(),
            self.cental_dir_entries_total.to_le_bytes().to_vec(),
            self.central_dir_size.to_le_bytes().to_vec(),
            self.central_dir_offset.to_le_bytes().to_vec(),
            self.comment_length.to_le_bytes().to_vec(),
            self.comment.to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for EOCD<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let pos = value
            .windows(4)
            .rev()
            .position(|w| w == [0x50, 0x4b, 0x5, 0x6])
            .ok_or(anyhow!("EOCD not found"))?;

        if pos >= u16::MAX as usize + 22 {
            return Err(anyhow!("EOCD not found"));
        }

        let pos = value.len() - (pos + 4);

        let signature = u32::from_le_bytes(value[pos..pos + 4].try_into()?);
        let disk_number = u16::from_le_bytes(value[pos + 4..pos + 6].try_into()?);
        let central_dir_start_disk = u16::from_le_bytes(value[pos + 6..pos + 8].try_into()?);
        let cental_dir_entries_in_disk = u16::from_le_bytes(value[pos + 8..pos + 10].try_into()?);
        let cental_dir_entries_in_total = u16::from_le_bytes(value[pos + 10..pos + 12].try_into()?);
        let central_dir_size = u32::from_le_bytes(value[pos + 12..pos + 16].try_into()?);
        let central_dir_offset = u32::from_le_bytes(value[pos + 16..pos + 20].try_into()?);
        let comment_length = u16::from_le_bytes(value[pos + 20..pos + 22].try_into()?);

        let start = pos + 22;
        let stop = pos + 22 + comment_length as usize;
        if stop as usize > value.len() {
            return Err(anyhow!("invalid comment_length"));
        }
        let comment = &value[start..stop];

        assert_eq!(comment_length as usize, comment.len());

        Ok(Self {
            signature,
            disk_number,
            central_dir_start_disk,
            cental_dir_entries_disk: cental_dir_entries_in_disk,
            cental_dir_entries_total: cental_dir_entries_in_total,
            central_dir_size,
            central_dir_offset,
            comment_length,
            comment,
        })
    }
}
