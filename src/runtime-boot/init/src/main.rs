extern crate libc;
extern crate serde;
extern crate serde_json;

use libc::syscall;

use nix::mount::MsFlags;
use std::env;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{ErrorKind, Read};

use anyhow::{anyhow, Result};
use std::ffi::CString;
use std::mem::size_of;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    
    let agent_boot = matches!(env::var("ENCLAVE_AGENT"), Ok(val) if val == "true" || val == "TRUE" || val == "1");
    println!("agent_boot {}", agent_boot);

    // Mount the image
    const SYS_MOUNT_FS: i64 = 363;

    let ret = match agent_boot {
        true => {
            let root_config_ptr: *const i8 = std::ptr::null();
            unsafe { syscall(SYS_MOUNT_FS, root_config_ptr) }
        }
        false => {
            let rootfs_upper_layer = "/sefs/upper";
            let rootfs_lower_layer = "/sefs/lower";
            let rootfs_entry = "/";
            let rootfs_key = b"c7-32-b3-ed-44-df-ec-7b-25-2d-9a-32-38-8d-58-61";

            // Create and mount directory for fs key from agent enclave
            fs::create_dir("/mnt");
            let fs_type = String::from("sefs");
            let source = Path::new("/host");
            let mount_path = Path::new("/mnt");
            let flags = MsFlags::empty();
            let source_c = CString::new(source.to_str().unwrap()).unwrap();
            let mountpoint_c = CString::new(mount_path.to_str().unwrap()).unwrap();

            let options = format!(
                "dir={}",
                Path::new("/keys").display()//Path::new("/keys").join("scratch-base_v1.8").join("lower").display(),
                
            );
            nix::mount::mount(
                Some(fs_type.as_str()),
                mountpoint_c.as_c_str(),
                Some(fs_type.as_str()),
                flags,
                Some(options.as_str()),
            )
            .unwrap_or_else(|err| {
                eprintln!("Error reading file: {}", err);
        });
            
            let root_path = "/"; // Change this to the root path you want to start from
            let depth = 2; // Set the desired depth

            list_entries(root_path, depth);

            let KEY_FILE: &str = "/mnt/key.txt";
            let contents = fs::read_to_string(&KEY_FILE)
                .unwrap_or_else(|err| {
                    eprintln!("Error reading file: {}", err);
                    String::new() // or any other default value or behavior you want
            });
            // println!("file contents: {}", contents);
            // Get the key of FS image
            // let key = {
            //     let key_str = load_key(KEY_FILE)?;
            //     let mut key: sgx_key_128bit_t = Default::default();
            //     parse_str_to_bytes(&key_str, &mut key)?;
            //     Some(key)
            // };
            let key = {
                const IMAGE_KEY_FILE: &str = "/etc/image_key";
                // TODO: Get the key through RA or LA
                let mut file = File::create(IMAGE_KEY_FILE)?;
                // Writes key.
                file.write_all(rootfs_key)?;
        
                let key_str = load_key(IMAGE_KEY_FILE)?;
                let mut key: sgx_key_128bit_t = Default::default();
                parse_str_to_bytes(&key_str, &mut key)?;
                Some(key)
            };

            let key_ptr = key
                .as_ref()
                .map(|key| key as *const sgx_key_128bit_t)
                .unwrap_or(std::ptr::null());

            // Example envs. must end with null
            let env1 = CString::new("TEST=1234").unwrap();
            let envp = [env1.as_ptr(), std::ptr::null()];
            // Set rootfs parameters
            let upper_layer_path = CString::new(rootfs_upper_layer).expect("CString::new failed");
            let lower_layer_path = CString::new(rootfs_lower_layer).expect("CString::new failed");
            let entry_point = CString::new(rootfs_entry).expect("CString::new failed");
            let hostfs_source = CString::new("/tmp").expect("CString::new failed");
            let rootfs_config: user_rootfs_config = user_rootfs_config {
                len: size_of::<user_rootfs_config>(),
                upper_layer_path: upper_layer_path.as_ptr(),
                lower_layer_path: lower_layer_path.as_ptr(),
                entry_point: entry_point.as_ptr(),
                hostfs_source: hostfs_source.as_ptr(),
                hostfs_target: std::ptr::null(),
                envp: envp.as_ptr(),
            };
            println!("key_ptr: {:p}", key_ptr);
            let key_null_ptr: *const i8 = std::ptr::null();
            unsafe { syscall(SYS_MOUNT_FS, key_ptr, &rootfs_config) }
        }
    };
    if ret < 0 {
        println!("ret is : {}", ret);
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[allow(non_camel_case_types)]
type sgx_key_128bit_t = [u8; 16];

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
struct user_rootfs_config {
    // length of the struct
    len: usize,
    // UnionFS type rootfs upper layer, read-write layer
    upper_layer_path: *const i8,
    // UnionFS type rootfs lower layer, read-only layer
    lower_layer_path: *const i8,
    entry_point: *const i8,
    // HostFS source path
    hostfs_source: *const i8,
    // HostFS target path, default value is "/host"
    hostfs_target: *const i8,
    // An array of pointers to null-terminated strings
    // and must be terminated by a null pointer
    envp: *const *const i8,
}

fn load_key(key_path: &str) -> Result<String, Box<dyn Error>> {
    let mut key_file = File::open(key_path)?;
    let mut key = String::new();
    key_file.read_to_string(&mut key)?;
    Ok(key.trim_end_matches(|c| c == '\r' || c == '\n').to_string())
}

fn parse_str_to_bytes(arg_str: &str, bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let bytes_str_vec = {
        let bytes_str_vec: Vec<&str> = arg_str.split('-').collect();
        if bytes_str_vec.len() != bytes.len() {
            return Err(Box::new(std::io::Error::new(
                ErrorKind::InvalidData,
                "The length or format of Key/MAC string is invalid",
            )));
        }
        bytes_str_vec
    };

    for (byte_i, byte_str) in bytes_str_vec.iter().enumerate() {
        bytes[byte_i] = u8::from_str_radix(byte_str, 16)?;
    }
    Ok(())
}

fn list_entries(path: &str, depth: usize) {
    if depth == 0 {
        return;
    }

    println!("Listing entries in: {}", path);

    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    let entry_path = entry.path();

                    if entry_path.is_dir() {
                        println!("Directory: {}", entry_path.display());
                        // Recursively list entries one level deeper
                        list_entries(&entry_path.to_string_lossy(), depth - 1);
                    } else {
                        println!("File: {}", entry_path.display());
                    }
                } else {
                    // Log the error and continue with the next entry
                    eprintln!("Error reading directory entry: {:?}", entry.err());
                }
            }
        }
        Err(err) => {
            // Log the error and continue
            eprintln!("Error reading directory: {}", err);
        }
    }
}