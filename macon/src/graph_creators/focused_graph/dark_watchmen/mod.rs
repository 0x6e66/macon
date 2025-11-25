use std::{
    fs::{File, remove_file},
    io::{Read, Write},
    process::Command,
};

use anyhow::{Result, anyhow};
use arangors::Document;
use indicatif::ProgressIterator;
use macon_cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_index,
};
use sha256::digest;

use crate::{
    cli::VMArgs,
    graph_creators::focused_graph::{
        FocusedCorpus, FocusedGraph, HasMalwareFamily,
        dark_watchmen::nodes::{
            DarkWatchmen, DarkWatchmenHasJS, DarkWatchmenHasPE, DarkWatchmenJS, DarkWatchmenPE,
        },
    },
};

pub mod nodes;

impl FocusedGraph {
    pub fn dark_watchmen_main(
        &self,
        vm_args: &VMArgs,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let db = self.get_db();
        let idx = vec!["sha256sum".to_string()];

        // Create index for sha256sum field
        ensure_index::<DarkWatchmenPE>(db, idx.clone())?;
        ensure_index::<DarkWatchmenJS>(db, idx.clone())?;

        let main_node = self.dark_watchmen_create_main_node(corpus_node)?;

        let mut errors = Vec::new();

        vm_args.main_args.files.iter().progress().for_each(|entry| {
            match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => {
                            match self.dark_watchmen_handle_sample(
                                &format!("{entry:?}"),
                                &buf,
                                &main_node,
                                vm_args,
                            ) {
                                Ok(_) => (),
                                Err(e) => errors.push(e),
                            }
                        }
                        Err(e) => errors.push(e.into()),
                    }
                }
                Err(e) => errors.push(e.into()),
            }
        });

        for e in errors.iter() {
            eprintln!("{e}");
        }

        Ok(())
    }

    fn dark_watchmen_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<Document<DarkWatchmen>> {
        let main_node_data = DarkWatchmen {
            name: "DarkWatchmen".to_string(),
            display_name: "DarkWatchmen".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node(main_node_data, "name", "DarkWatchmen")?;

        self.upsert_edge::<FocusedCorpus, DarkWatchmen, HasMalwareFamily>(corpus_node, &main_node)?;

        Ok(main_node)
    }

    fn dark_watchmen_handle_sample(
        &self,
        sample_filename: &str,
        sample_data: &[u8],
        main_node: &Document<DarkWatchmen>,
        vm_args: &VMArgs,
    ) -> Result<()> {
        match detect_sample_type(sample_data) {
            Some(SampleType::PE) => {
                let pe_node = self.dark_watchmen_create_pe_node(sample_data, vm_args)?;
                self.upsert_edge::<DarkWatchmen, DarkWatchmenPE, DarkWatchmenHasPE>(
                    main_node, &pe_node,
                )?;
            }
            Some(SampleType::JS) => {
                self.dark_watchmen_create_js_node(sample_data)?;
            }
            None => {
                return Err(anyhow!(
                    "Sample type of the sample {sample_filename} could not be detected"
                ));
            }
        }

        Ok(())
    }

    fn dark_watchmen_create_pe_node(
        &self,
        sample_data: &[u8],
        vm_args: &VMArgs,
    ) -> Result<Document<DarkWatchmenPE>> {
        let sha256sum = digest(sample_data);

        let pe_node_data = DarkWatchmenPE {
            sha256sum: sha256sum.clone(),
        };

        // Intentionally out of regular order to prevent PEs from being created without their JS
        // stage if the extraction fails
        let js_data = get_js_from_pe_dynamically(sample_data, vm_args)?;

        let UpsertResult {
            document: pe_node,
            created,
        } = self.upsert_node::<DarkWatchmenPE>(pe_node_data, "sha256sum", &sha256sum)?;

        // Sample is already in DB => no need for further analysis
        if !created {
            return Ok(pe_node);
        }

        let js_node = self.dark_watchmen_create_js_node(&js_data)?;
        self.upsert_edge::<DarkWatchmenPE, DarkWatchmenJS, DarkWatchmenHasJS>(&pe_node, &js_node)?;

        Ok(pe_node)
    }

    fn dark_watchmen_create_js_node(&self, sample_data: &[u8]) -> Result<Document<DarkWatchmenJS>> {
        let sha256sum = digest(sample_data);

        let js_node_data = DarkWatchmenJS {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: js_node,
            created: _,
        } = self.upsert_node::<DarkWatchmenJS>(js_node_data, "sha256sum", &sha256sum)?;

        Ok(js_node)
    }
}

enum SampleType {
    PE,
    JS,
}

fn detect_sample_type(sample_data: &[u8]) -> Option<SampleType> {
    if sample_data.len() < 4 {
        return None;
    }

    // check of PE magic numbers
    if sample_data[0..2] == [0x4D, 0x5A] || sample_data[0..4] == [0x50, 0x45, 0x00, 0x00] {
        Some(SampleType::PE)
    // TODO: implement check for js stage
    } else {
        Some(SampleType::JS)
    }
}

/// Extract the JavaScript payload from a PE file (dynamically)
///
///     #############################################################################
///     #                                                                           #
///     #                               WARNING                                     #
///     #                                                                           #
///     #       The VM will be used to actually run the samples. Make sure          #
///     #       you properly isolated the VM from your surrounding environemnt      #
///     #                                                                           #
///     #############################################################################
///
/// Prerequisites for the dynamic extraction of the JavaScript payload
///   - A running Windows VM with VirtualBox as Hypervisor
///   - A shared folder for the Windows VM which is mounted on `T:`
///   - Disabled Windows Security Features
///     1. **Disable Windows Defender:**
///        - Navigate to **Settings > Update & Security > Windows Security > Virus & threat protection**.
///        - Under "Virus & threat protection settings," click **"Manage settings"**.
///        - Turn off **"Real-time protection"**.
///     2. **Disable Windows Firewall:**
///        - Open the **Control Panel** and go to **System and Security > Windows Defender Firewall**.
///        - Click **"Turn Windows Defender Firewall on or off"** in the left pane.
///        - Select **"Turn off Windows Defender Firewall"** for both private and public networks.
///     3. **Disable Windows Updates:**
///        - Press `Windows + R`, type `services.msc`, and press `Enter`.
///        - Find the **"Windows Update"** service, double-click it, and change the **"Startup type"** to **"Disabled"**. Click **"Apply"** and **"OK"**.
fn get_js_from_pe_dynamically(sample_data: &[u8], vm_args: &VMArgs) -> Result<Vec<u8>> {
    let VMArgs {
        main_args: _,
        vm_name,
        vm_user,
        vm_pass,
        shared_dir,
    } = vm_args;

    // Write the sample_data to a file in the shared directory on the host
    let mal_path = shared_dir.join("mal.exe");
    let mut mal = File::create(&mal_path)?;
    mal.write_all(sample_data)?;

    // execute the malware sample inside the VM
    let _ = Command::new("VBoxManage")
        .args(["guestcontrol", vm_name, "run"])
        .args(["--username", vm_user])
        .args(["--password", vm_pass])
        .args([
            "--exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ])
        .args(["--", "Start-Process"])
        .args(["-FilePath", r"T:\mal.exe"])
        .output();

    let _ = remove_file(mal_path);

    // move the dropped JavaScript file to the shared directory inside the VM
    let _ = Command::new("VBoxManage")
        .args(["guestcontrol", vm_name, "run"])
        .args(["--username", vm_user])
        .args(["--password", vm_pass])
        .args([
            "--exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ])
        .args(["--", "Move-Item"])
        .args([
            "-Path",
            r"C:\Users\vboxuser\AppData\*\*\*.js,C:\Users\vboxuser\AppData\*\*.js",
        ])
        .args(["-Destination", r"T:\dropped.js"])
        .output();

    let dropped_js_path = shared_dir.join("dropped.js");

    let mut js_file = File::open(&dropped_js_path)?;
    let mut js_sample_data = vec![];
    js_file.read_to_end(&mut js_sample_data)?;

    remove_file(dropped_js_path)?;

    Ok(js_sample_data)
}
