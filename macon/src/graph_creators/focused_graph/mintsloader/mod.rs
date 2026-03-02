pub mod nodes;

use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use arangors::Document;
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, general_purpose::PAD},
};
use flate2::bufread::GzDecoder;
use indicatif::ParallelProgressIterator;
use lazy_static::lazy_static;
use macon_cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_index,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use sha256::digest;
use shunting::{MathContext, ShuntingParser};

use crate::{
    graph_creators::focused_graph::{
        FocusedCorpus, FocusedGraph, HasMalwareFamily,
        mintsloader::nodes::{
            Mintsloader, MintsloaderCS, MintsloaderHasCS, MintsloaderHasPs, MintsloaderHasX509Cert,
            MintsloaderPs, MintsloaderPsKind, MintsloaderX509Cert,
        },
    },
    utils::get_string_from_binary,
};

lazy_static! {
    static ref RE_FUNCTION: Regex = {
        let s = r#"function\s+(?<function>[A-z0-9]+)\s+\{param\([^\)]+\)"#;
        Regex::new(s).unwrap()
    };
    static ref RE_KEY: Regex = {
        let s = r#"\("(?<key>[A-z0-9]{12})"\)"#;
        Regex::new(s).unwrap()
    };
}

impl FocusedGraph {
    pub fn mintsloader_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let db = self.get_db();
        let idx = vec!["sha256sum".to_string()];

        // Create index for sha256sum field
        ensure_index::<MintsloaderPs>(db, idx.clone())?;
        ensure_index::<MintsloaderCS>(db, idx.clone())?;
        ensure_index::<MintsloaderX509Cert>(db, idx)?;

        let main_node = self.mintsloader_create_main_node(corpus_node)?;

        let errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));

        files
            .par_iter()
            .progress()
            .for_each(|entry| match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => {
                            match self.mintsloader_handle_sample(
                                &format!("{entry:?}"),
                                &buf,
                                &main_node,
                            ) {
                                Ok(_) => (),
                                Err(e) => errors.lock().unwrap().push(e),
                            }
                        }
                        Err(e) => errors.lock().unwrap().push(e.into()),
                    }
                }
                Err(e) => errors.lock().unwrap().push(e.into()),
            });

        for e in errors.lock().unwrap().iter() {
            eprintln!("{e}");
        }

        Ok(())
    }

    fn mintsloader_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<Document<Mintsloader>> {
        let mintsloader = Mintsloader {
            name: "Mintsloader".to_string(),
            display_name: "Mintsloader".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node::<Mintsloader>(mintsloader, "name", "Mintsloader")?;

        self.upsert_edge::<FocusedCorpus, Mintsloader, HasMalwareFamily>(corpus_node, &main_node)?;

        Ok(main_node)
    }

    fn mintsloader_handle_sample(
        &self,
        sample_filename: &str,
        sample_data: &[u8],
        main_node: &Document<Mintsloader>,
    ) -> Result<()> {
        let Some(sample_type) = detect_sample_type(sample_data) else {
            return Err(anyhow!(
                "Sample type of the sample {sample_filename} could not be detected"
            ));
        };

        match sample_type {
            SampleType::PS(ps_kind) => {
                let ps_node = self.mintsloader_create_ps_node(sample_data, ps_kind)?;
                self.upsert_edge::<Mintsloader, MintsloaderPs, MintsloaderHasPs>(
                    main_node, &ps_node,
                )?;
            }
            SampleType::CS => {
                self.mintsloader_create_cs_node(sample_data)?;
            }
            SampleType::X509 => {
                self.mintsloader_create_x509_node(sample_data)?;
            }
        }

        Ok(())
    }

    fn mintsloader_create_ps_node(
        &self,
        sample_data: &[u8],
        ps_kind: PSKind,
    ) -> Result<Document<MintsloaderPs>> {
        match ps_kind {
            PSKind::Xor_B64(xor_key, base64) => {
                self.mintsloader_create_ps_xor_node(sample_data, &xor_key, &base64)
            }
            PSKind::DGA_iex => self.mintsloader_create_ps_dga_iex_node(sample_data),
            PSKind::Start_Process => self.mintsloader_create_ps_start_process_node(sample_data),
            PSKind::Two_Liner => self.mintsloader_create_ps_two_liner_node(sample_data),
        }
    }

    fn mintsloader_create_ps_xor_node(
        &self,
        sample_data: &[u8],
        xor_key: &str,
        base64: &str,
    ) -> Result<Document<MintsloaderPs>> {
        let sha256sum = digest(sample_data);

        let ps_xor_data = MintsloaderPs {
            sha256sum: sha256sum.clone(),
            kind: MintsloaderPsKind::XorBase64,
        };

        let UpsertResult {
            document: ps_xor_node,
            created,
        } = self.upsert_node::<MintsloaderPs>(ps_xor_data, "sha256sum", &sha256sum)?;

        // Sample is already in DB => no need for further analysis
        if !created {
            return Ok(ps_xor_node);
        }

        // extract next stage
        let next_stage = decode_base64_with_xor_key(xor_key, base64)?;
        if next_stage.contains("$executioncontext;") {
            let ps_dga_iex_node = self.mintsloader_create_ps_dga_iex_node(next_stage.as_bytes())?;
            self.upsert_edge::<MintsloaderPs, MintsloaderPs, MintsloaderHasPs>(
                &ps_xor_node,
                &ps_dga_iex_node,
            )?;
        } else if next_stage.contains("start-process powershell") {
            let ps_start_process_node =
                self.mintsloader_create_ps_start_process_node(next_stage.as_bytes())?;
            self.upsert_edge::<MintsloaderPs, MintsloaderPs, MintsloaderHasPs>(
                &ps_xor_node,
                &ps_start_process_node,
            )?;
        }

        // check for C# code snippet and X.509 certificate
        self.mintsloader_extract_cs_and_cert_from_ps(sample_data, &ps_xor_node)?;

        Ok(ps_xor_node)
    }

    fn mintsloader_create_ps_dga_iex_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderPs>> {
        let sha256sum = digest(sample_data);

        let ps_dga_iex_data = MintsloaderPs {
            sha256sum: sha256sum.clone(),
            kind: MintsloaderPsKind::DgaIex,
        };

        let UpsertResult {
            document: ps_dga_iex_node,
            created: _,
        } = self.upsert_node::<MintsloaderPs>(ps_dga_iex_data, "sha256sum", &sha256sum)?;

        Ok(ps_dga_iex_node)
    }

    fn mintsloader_create_ps_start_process_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderPs>> {
        let sha256sum = digest(sample_data);

        let ps_start_process_data = MintsloaderPs {
            sha256sum: sha256sum.clone(),
            kind: MintsloaderPsKind::StartProcess,
        };

        let UpsertResult {
            document: ps_start_process_node,
            created: _,
        } = self.upsert_node::<MintsloaderPs>(ps_start_process_data, "sha256sum", &sha256sum)?;

        Ok(ps_start_process_node)
    }

    fn mintsloader_create_ps_two_liner_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderPs>> {
        let sha256sum = digest(sample_data);

        let ps_two_liner_data = MintsloaderPs {
            sha256sum: sha256sum.clone(),
            kind: MintsloaderPsKind::TwoLiner,
        };

        let UpsertResult {
            document: ps_two_liner_node,
            created,
        } = self.upsert_node::<MintsloaderPs>(ps_two_liner_data, "sha256sum", &sha256sum)?;

        // Sample was not created => already in db => can be aborted here
        if !created {
            return Ok(ps_two_liner_node);
        }

        // check for C# code snippet and X.509 certificate
        self.mintsloader_extract_cs_and_cert_from_ps(sample_data, &ps_two_liner_node)?;

        Ok(ps_two_liner_node)
    }

    fn mintsloader_create_cs_node(&self, sample_data: &[u8]) -> Result<Document<MintsloaderCS>> {
        let sha256sum = digest(sample_data);

        let ps_cs_data = MintsloaderCS {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_cs_node,
            created: _,
        } = self.upsert_node::<MintsloaderCS>(ps_cs_data, "sha256sum", &sha256sum)?;

        Ok(ps_cs_node)
    }

    fn mintsloader_create_x509_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderX509Cert>> {
        let base64_decoder = GeneralPurpose::new(&alphabet::STANDARD, PAD);
        let sample_data = base64_decoder.decode(sample_data)?;

        let sha256sum = digest(sample_data);

        let ps_x509_data = MintsloaderX509Cert {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_x509_node,
            created: _,
        } = self.upsert_node::<MintsloaderX509Cert>(ps_x509_data, "sha256sum", &sha256sum)?;

        Ok(ps_x509_node)
    }

    fn mintsloader_extract_cs_and_cert_from_ps(
        &self,
        sample_data: &[u8],
        ps_node: &Document<MintsloaderPs>,
    ) -> Result<()> {
        let sample_str = get_string_from_binary(sample_data);
        let strings = get_deobfuscated_strings_from_sample_sorted(&sample_str);
        for i in 0..2 {
            if let Some(string) = strings.get(i) {
                if string.starts_with("MIIE") {
                    let x509_node = self.mintsloader_create_x509_node(string.as_bytes())?;
                    self.upsert_edge::<MintsloaderPs, MintsloaderX509Cert, MintsloaderHasX509Cert>(
                        ps_node, &x509_node,
                    )?;
                } else if string.starts_with("using System") {
                    let cs_node = self.mintsloader_create_cs_node(string.as_bytes())?;
                    self.upsert_edge::<MintsloaderPs, MintsloaderCS, MintsloaderHasCS>(
                        ps_node, &cs_node,
                    )?;
                }
            }
        }

        Ok(())
    }
}

fn extract_key_and_base64_from_ps_xor_base64(sample_str: &str) -> Result<(&str, &str)> {
    let function_name = RE_FUNCTION
        .captures(sample_str)
        .map(|c| c.extract::<1>())
        .map(|(_, [c])| c);

    let Some(function_name) = function_name else {
        return Err(anyhow!("Could not find function"));
    };

    let xor_key = RE_KEY
        .captures(sample_str)
        .map(|c| c.extract::<1>())
        .map(|(_, [c])| c);

    let s = r#"\s+"(?<base64>[A-z0-9+/=]+)""#;
    let s = format!("{function_name}{s}");
    let re = Regex::new(&s).unwrap();
    let base64 = re
        .captures(sample_str)
        .map(|c| c.extract::<1>())
        .map(|(_, [c])| c);

    let res = xor_key.zip(base64).ok_or(anyhow!(
        "Could not extract xor key and base64 blob from sample"
    ))?;

    Ok(res)
}

fn decode_base64_with_xor_key(xor_key: &str, base64: &str) -> Result<String> {
    let base64_decoder = GeneralPurpose::new(&alphabet::STANDARD, PAD);
    let mut res = base64_decoder.decode(base64)?;

    let xor_key = xor_key.as_bytes();
    for i in 0..res.len() {
        res[i] ^= xor_key[i % xor_key.len()];
    }

    let cursor = Cursor::new(res);
    let mut gzip_decoder = GzDecoder::new(cursor);
    let mut s = String::new();

    gzip_decoder.read_to_string(&mut s)?;

    Ok(s)
}

#[allow(non_camel_case_types)]
enum PSKind {
    /// Sample is a powershell script.
    /// It has a base64 encoded blob, which is
    ///     1. base64-decoded and
    ///     2. "decrypted" with a static xor key and
    ///     3. gzip-decoded
    ///
    /// Produces [`SampleType::PS_DGA_iex`] xor [`SampleType::PS_Start_Process`]
    ///
    /// This enum contains the xor key and the base64 blob of the sample like this:
    /// `SampleType::PS_Xor_B64(xor_key, base64)`
    Xor_B64(String, String),

    /// Sample is a powershell script.
    /// It runs a dga, contacts the generated url and pipes the response in iex
    DGA_iex,

    /// Sample is a powershell script.
    /// It starts a new powershell process with a new alias "rzs"
    Start_Process,

    /// Sample is a powershell script with about two lines
    /// Has obfuscated strings that contain
    ///     1. a C# code snippet ([`SampleType::CS`]) and
    ///     2. a x509 certificate ([`SampleType::X509`])
    Two_Liner,
}

#[allow(non_camel_case_types)]
enum SampleType {
    /// PS
    PS(PSKind),

    /// C# code snippet contained inside [`SampleType::PSKind::Two_Liner`]
    CS,

    /// X.509 certificate contained inside [`SampleType::PSKind::Two_Liner`]
    X509,
}

fn detect_sample_type(sample_data: &[u8]) -> Option<SampleType> {
    let sample_str = get_string_from_binary(sample_data);

    if let Ok((xor_key, base64)) = extract_key_and_base64_from_ps_xor_base64(&sample_str) {
        return Some(SampleType::PS(PSKind::Xor_B64(
            xor_key.to_owned(),
            base64.to_owned(),
        )));
    } else if sample_str
        .find("$executioncontext;")
        .and(
            sample_str
                .find("$global:block=(curl")
                .or(sample_str.find("iex(curl")),
        )
        .is_some()
    {
        return Some(SampleType::PS(PSKind::DGA_iex));
    } else if sample_str.contains("start-process powershell") {
        return Some(SampleType::PS(PSKind::Start_Process));
    } else if sample_str.trim().starts_with("using System") {
        return Some(SampleType::CS);
    } else if sample_str.trim().starts_with("MIIE") {
        return Some(SampleType::X509);
    } else if sample_str.lines().collect::<Vec<&str>>().len() < 5 {
        return Some(SampleType::PS(PSKind::Two_Liner));
    }

    None
}

fn get_deobfuscated_strings_from_sample_sorted(sample_str: &str) -> Vec<String> {
    let mut strs: Vec<String> = get_obfuscated_strings_from_sample(sample_str)
        .iter()
        .map(|obs| deobfuscate_string(obs))
        .filter_map(|s| s.ok())
        .collect();

    strs.sort_by_key(|s| std::cmp::Reverse(s.len()));

    strs
}

fn deobfuscate_string(obfuscated_string: &str) -> Result<String> {
    let mut res = String::new();

    // evaluate each obfuscated character in the string using the "Shunting Yard" algorithm
    for obfuscated_char in obfuscated_string.split(",") {
        let expr = ShuntingParser::parse_str(obfuscated_char).map_err(|e| anyhow!(e))?;
        let result = MathContext::new().eval(&expr).map_err(|e| anyhow!(e))? as u8;

        res.push(result.into());
    }

    Ok(res)
}

fn get_obfuscated_strings_from_sample(sample_str: &str) -> Vec<String> {
    let mut obfuscated_strings = vec![];

    for (j, _) in sample_str.match_indices("@(") {
        let mut pos = 1;
        let mut i = j + 2;

        // indicates that obfuscated_string is not ascii, because char boundary was crossed
        let mut failed = false;

        while pos != 0 && i < sample_str.len() {
            // check is char boundary gets crossed
            if !(sample_str.is_char_boundary(i) && sample_str.is_char_boundary(i + 1)) {
                failed = true;
                break;
            }

            if &sample_str[i..i + 1] == "(" {
                pos += 1;
            }
            if &sample_str[i..i + 1] == ")" {
                pos -= 1;
            }
            i += 1;
        }

        if !failed {
            let tmp = &sample_str[j + 2..i - 1].trim();
            if !tmp.is_empty() {
                obfuscated_strings.push(tmp.to_string());
            }
        }
    }

    obfuscated_strings
}
