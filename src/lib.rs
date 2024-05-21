// hk-passwordm - Simple password manager using Fyne for GUI and Rust
// Copyright (C) 2024 Hlib Korzhynskyy
// 
// This program is free software: you can redistribute it and/or modify it under the terms of
// the GNU General Public License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this
// program. If not, see <https://www.gnu.org/licenses/>.

use chacha20poly1305::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, KeyInit, OsRng}, XChaCha20Poly1305
};
// use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::str;
use libc::c_char;
use std::ffi::{CStr, CString};

// Used to fill random bytes for containers that require a certain size
// As an example, nonce of a certain length.
fn fill_random_bytes(slice_to_fill: &[u8], target_length: usize) -> (Vec<u8>, u8) {
    if slice_to_fill.len() < target_length {
        let mut add_numbers = vec![0u8; (target_length - slice_to_fill.len()).into()];
        match OsRng.try_fill_bytes(&mut add_numbers) {
            Ok(_) => (),
            Err(_) => return (vec![], 1),
        };
        let mut full_slice = slice_to_fill.to_vec();
        full_slice.append(&mut add_numbers);
        return (full_slice, 0);
    }else{
        return (slice_to_fill[..target_length].to_vec(), 0);
    }
}

// Adds padding to the file. This a message to have bytes that are multiple of the block size
fn add_padding(slice_to_pad: &[u8]) -> (Vec<u8>, u8) {
    let mut padded_slice: Vec<u8> = slice_to_pad.to_vec();
    if padded_slice.len() % 64 != 0 {
        padded_slice.push(60);
        let (padded_slice, err) = fill_random_bytes(&padded_slice, padded_slice.len() + (64 - (padded_slice.len() % 64)));
        if err != 0 {
            return (vec![], err);
        }
        return (padded_slice, 0)
    }
    return (padded_slice, 0);
}

// Removes the paddings. This allows the message to be read with readable utf-8 characters
fn remove_padding(slice_remove_pad: &[u8]) -> (Vec<u8>, u8) {
    let padded_slice: Vec<u8> = slice_remove_pad.to_vec();
    let mut i = padded_slice.len() - 64;
    loop {
        if padded_slice[i] == 60 || i >= padded_slice.len() - 1{
            break;
        }
        i += 1;
    }
    return (padded_slice[..i].to_vec(), 0);
}

#[no_mangle]
pub extern "C" fn create_password_file(file_location: *const c_char, key: *const c_char) -> i32 {
    // convert C char string to Rust string literals
    let file_location_c: &CStr = unsafe { CStr::from_ptr(file_location) };
    let file_location = match file_location_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let key_c: &CStr = unsafe { CStr::from_ptr(key) };
    let key = key_c.to_bytes();

    if key.len() < 32 {
        return 1
    }
    let key = GenericArray::clone_from_slice(&key[..32]);
    let cipher = XChaCha20Poly1305::new(&key);

    // Generates the extended nonce used to encrypt the header
    let generate_nonce = {
        let begin = "".as_bytes();
        let (filled_slice, err) = fill_random_bytes(begin, 24);
        if err != 0 {
            return 2;
        }else {
            filled_slice
        }
    };
    let nonce = GenericArray::clone_from_slice(&generate_nonce);

    let (text_to_encrypt, err) = add_padding(b"HK PASSWORD MANAGER FILE");
    if err != 0 {
        return 2;
    }

    let ciphertext = match cipher.encrypt(&nonce, text_to_encrypt.as_ref()) {
        Ok(enc) => enc,
        Err(_) => return 3,
    };

    let mut file = match File::create(file_location) {
        Ok(f) => f,
        Err(_) => return 4,
    };

    let line_to_write = [generate_nonce.as_slice(), ciphertext.as_slice(), b"EMHKPSWD".as_slice()].concat();

    match file.write_all(&line_to_write) {
        Ok(_) => (),
        Err(_) => return 4,
    };

    return 0
}

fn read_header(file_location: &str, key: &[u8]) -> (String, u8) {
    let key = GenericArray::clone_from_slice(&(key)[..32]);

    let mut buffer = [0u8; 8];
    let mut f = match File::open(file_location) {
        Ok(f) => f,
        Err(_) => return (String::from(""), 1),
    };
    let mut nonce = vec!(0u8; 24);
    match f.read_exact(&mut nonce) {
        Ok(_) => (),
        Err(_) => return (String::from(""), 2),
    };

    let nonce = &nonce;

    let nonce = GenericArray::clone_from_slice(&nonce);

    // Reads up until detecting the message separator. This can be anything.
    // EMHKPSWD was chosen as it is 8 bytes in length. Block sizes and nonce can be divided by 8
    while &buffer != b"EMHKPSWD" {
        match f.read_exact(&mut buffer) {
            Ok(_) => (),
            Err(_) => return (String::from(""), 2),
        };
    }

    let end_cursor = f.stream_position().unwrap();
    match f.seek(SeekFrom::Start(24)) {
        Ok(_) => (),
        Err(_) => return (String::from(""), 2),
    };

    let mut encrypted_message = vec![0u8; (end_cursor-32) as usize];
    match f.read_exact(&mut encrypted_message) {
        Ok(_) => (),
        Err(_) => return (String::from(""), 2),
    };

    let cipher = XChaCha20Poly1305::new(&key);

    let decrypted_message = match cipher.decrypt(&nonce, encrypted_message.as_ref()) {
        Ok(m) => m,
        Err(_) => return (String::from(""), 3),
    };

    let (unpadded_message, _) = remove_padding(&decrypted_message);

    let utf8_decoded = match str::from_utf8(&unpadded_message) {
        Ok(m) => m,
        Err(_) => return (String::from(""), 3),
    };

    return (String::from(utf8_decoded), 0)
}

fn read_raw_message(file_location: &str, message_id: usize) -> (Vec<u8>, u8) {
    let mut buffer = [0u8; 8];

    let mut f = match File::open(file_location) {
        Ok(f) => f,
        Err(_) => return (vec![], 1),
    };
    let mut current_id: usize = 0;
    let mut past_cursor: usize = 0;
    let mut current_cursor: usize = 0;
    // Reads the entire file, skipping IDs that are not wanted.
    // Once the separator is encountered, a 1 is added to a counter
    // This counter represents the current message
    loop {
        while &buffer != b"EMHKPSWD" {
            match f.read_exact(&mut buffer) {
                Ok(_) => (),
                Err(_) => return (vec![], 2),
            };
            current_cursor += 8;
        }
        if message_id == current_id {
            match f.seek(SeekFrom::Start(past_cursor as u64)) {
                Ok(_) => (),
                Err(_) => return (vec![], 2),
            };

            let mut raw_message = vec![0u8; current_cursor - 8 - past_cursor];
            match f.read_exact(&mut raw_message) {
                Ok(_) => (),
                Err(_) => return (vec![], 2),
            };

            return (raw_message, 0);
        }else {
            current_id += 1;
            past_cursor = current_cursor;
            buffer = [0u8; 8];
        }
    }
}

#[no_mangle]
pub extern "C" fn add_account(file_location: *const c_char, key: *const c_char, account: *const c_char, username: *const c_char, password: *const c_char) -> i32 {
    // convert C char string to Rust string literals
    let file_location_c: &CStr = unsafe { CStr::from_ptr(file_location) };
    let file_location = match file_location_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let key_c: &CStr = unsafe { CStr::from_ptr(key) };
    let key = key_c.to_bytes();
    let account_c = unsafe { CStr::from_ptr(account) };
    let account = match account_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let username_c = unsafe { CStr::from_ptr(username) };
    let username = match username_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let password_c = unsafe { CStr::from_ptr(password) };
    let password = match password_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };

    let (current_header, err) = read_header(file_location, key);
    if err != 0 {
        return 1;
    }

    // Separates sthe header.
    // The first element in the header is always an irrelevant string
    // The header contains the accounts, allowing the access of accounts without
    // decrypting the entire file
    let mut header_parts = current_header.split("|").collect::<Vec<&str>>();
    let account_entry = format!("{}", account);

    match header_parts.iter().position(|&r| r == account) {
        Some(_) => return 10,
        None => (),
    };

    header_parts.push(&account_entry);

    let new_header = header_parts.join("|");

    let new_account = format!("{}|{}|{}", account, username, password);

    let key = GenericArray::clone_from_slice(&(key)[..32]);
    let cipher = XChaCha20Poly1305::new(&key);

    match File::create(format!("{}.new", file_location)) {
        _ => (),
    };

    let mut new_file = match OpenOptions::new().append(true).create(true).open(format!("{}.new", file_location)) {
        Ok(f) => f,
        Err(_) => return 4,
    };

    let (generate_nonce, err) = fill_random_bytes("".as_bytes(), 24);
    if err != 0 {
        return 2;
    }

    let nonce = GenericArray::clone_from_slice(&generate_nonce);

    let (new_header, err) = add_padding(new_header.as_bytes());
    if err != 0 {
        return 7;
    }

    let ciphertext = match cipher.encrypt(&nonce, new_header.as_ref()) {
        Ok(enc) => enc,
        Err(_) => return 3,
    };

    let line_to_write = [generate_nonce.as_slice(), ciphertext.as_slice(), b"EMHKPSWD".as_slice()].concat();

    match new_file.write(&line_to_write) {
        Ok(_) => (),
        Err(_) => return 4,
    };

    let mut i: usize = 1;
    // This code prepends existing messages to the file.
    // After the iteration, the new message is appended
    while i < (header_parts.len() - 1) {
        let (message, err) = read_raw_message(file_location, i);
        if err != 0 {
            return 8;
        }
        match new_file.write(&message) {
            Ok(_) => (),
            Err(_) => return 4,
        };
        match new_file.write(b"EMHKPSWD") {
            Ok(_) => (),
            Err(_) => return 4,
        };
        i += 1;
    }

    let (data_nonce, err) = fill_random_bytes(format!("{}", (header_parts.len() - 1)).as_bytes(), 24);
    if err != 0 {
        return 5;
    }
    let nonce = GenericArray::clone_from_slice(&data_nonce);

    let (new_account, err) = add_padding(new_account.as_bytes());
    if err != 0 {
        return 7;
    }

    let ciphertext = match cipher.encrypt(&nonce, new_account.as_ref()) {
        Ok(enc) => enc,
        Err(_) => return 3,
    };

    let line_to_write = [data_nonce.as_slice(), ciphertext.as_slice(), b"EMHKPSWD".as_slice()].concat();

    match new_file.write(&line_to_write) {
        Ok(_) => (),
        Err(_) => return 4,
    };

    return 0;
}

#[no_mangle]
pub extern "C" fn modify_account(file_location: *const c_char, key: *const c_char, account: *const c_char, username: *const c_char, password: *const c_char) -> i32 {
    // convert C char string to Rust string literals
    let file_location_c: &CStr = unsafe { CStr::from_ptr(file_location) };
    let file_location = match file_location_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let key_c: &CStr = unsafe { CStr::from_ptr(key) };
    let key = key_c.to_bytes();
    let account_c = unsafe { CStr::from_ptr(account) };
    let account = match account_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let username_c = unsafe { CStr::from_ptr(username) };
    let username = match username_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let password_c = unsafe { CStr::from_ptr(password) };
    let password = match password_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };

    let (current_header, err) = read_header(file_location, key);
    if err != 0 {
        return 1;
    }

    let header_parts = current_header.split("|").collect::<Vec<&str>>();

    let position = match header_parts.iter().position(|&r| r == account) {
        Some(i) => i,
        None => return 2,
    };

    let (mut message, err) = read_message(file_location, key, position);
    if err != 0 {
        return 3;
    }

    // The message is set to the new values and then joined again. Only the wanted message is
    // modified.
    if message[0] != account.to_string() {
        return 2;
    }

    message[1] = username.to_string();
    message[2] = password.to_string();

    let joined_message = message.join("|");

    let (data_nonce, err) = fill_random_bytes(format!("{}", (position)).as_bytes(), 24);
    if err != 0 {
        return 5;
    }
    let nonce = GenericArray::clone_from_slice(&data_nonce);

    let (new_account, err) = add_padding(joined_message.as_bytes());
    if err != 0 {
        return 7;
    }

    let key = GenericArray::clone_from_slice(&(key)[..32]);
    let cipher = XChaCha20Poly1305::new(&key);

    let ciphertext = match cipher.encrypt(&nonce, new_account.as_ref()) {
        Ok(enc) => enc,
        Err(_) => return 3,
    };

    let line_to_write = [data_nonce.as_slice(), ciphertext.as_slice(), b"EMHKPSWD".as_slice()].concat();

    match File::create(format!("{}.new", file_location)) {
        _ => (),
    };

    let mut new_file = match OpenOptions::new().append(true).create(true).open(format!("{}.new", file_location)) {
        Ok(f) => f,
        Err(_) => return 4,
    };

    let mut i: usize = 0;
    // If the message position does not equal to the position we are modifying, then the code
    // uses the existing message. Otherwise, writes the modified message to the file.
    while i < (header_parts.len()) {
        if i != position {
            let (message, err) = read_raw_message(file_location, i);
            if err != 0 {
                return 8;
            }
            match new_file.write(&message) {
                Ok(_) => (),
                Err(_) => return 4,
            };
            match new_file.write(b"EMHKPSWD") {
                Ok(_) => (),
                Err(_) => return 4,
            };
        }else {
            match new_file.write(&line_to_write) {
                Ok(_) => (),
                Err(_) => return 4,
            };
        }
        i += 1;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn delete_account(file_location: *const c_char, key: *const c_char, account: *const c_char) -> i32 {
    // convert C char string to Rust string literals
    let file_location_c: &CStr = unsafe { CStr::from_ptr(file_location) };
    let file_location = match file_location_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };
    let key_c: &CStr = unsafe { CStr::from_ptr(key) };
    let key = key_c.to_bytes();
    let account_c = unsafe { CStr::from_ptr(account) };
    let account = match account_c.to_str() {
        Ok(v) => v,
        Err(_) => return 9,
    };

    let (current_header, err) = read_header(file_location, key);
    if err != 0 {
        return 1;
    }

    let mut header_parts = current_header.split("|").collect::<Vec<&str>>();

    let position = match header_parts.iter().position(|&r| r == account) {
        Some(i) => i,
        None => return 2,
    };

    // Removes the account from the header, conserving header validity.
    header_parts.remove(position);

    let new_header = header_parts.join("|");

    let key = GenericArray::clone_from_slice(&(key)[..32]);
    let cipher = XChaCha20Poly1305::new(&key);

    let (generate_nonce, err) = fill_random_bytes("".as_bytes(), 24);
    if err != 0 {
        return 2;
    }

    let nonce = GenericArray::clone_from_slice(&generate_nonce);

    let (new_header, err) = add_padding(new_header.as_bytes());
    if err != 0 {
        return 7;
    }

    let ciphertext = match cipher.encrypt(&nonce, new_header.as_ref()) {
        Ok(enc) => enc,
        Err(_) => return 3,
    };

    let line_to_write = [generate_nonce.as_slice(), ciphertext.as_slice(), b"EMHKPSWD".as_slice()].concat();

    match File::create(format!("{}.new", file_location)) {
        _ => (),
    };

    let mut new_file = match OpenOptions::new().append(true).create(true).open(format!("{}.new", file_location)) {
        Ok(f) => f,
        Err(_) => return 4,
    };

    match new_file.write(&line_to_write) {
        Ok(_) => (),
        Err(_) => return 4,
    };

    let mut i: usize = 1;
    // Writes the messages from the old file to the new file. If the deleted account is encountered
    // then that message is skipped.
    while i < (header_parts.len() + 1) {
        if i != position {
            let (message, err) = read_raw_message(file_location, i);
            if err != 0 {
                return 8;
            }
            match new_file.write(&message) {
                Ok(_) => (),
                Err(_) => return 4,
            };
            match new_file.write(b"EMHKPSWD") {
                Ok(_) => (),
                Err(_) => return 4,
            };
        }
        i += 1;
    }

    return 0;
}

fn read_message(file_location: &str, key: &[u8], message_id: usize) -> (Vec<String>, u8) {
    let key = GenericArray::clone_from_slice(&(key)[..32]);
    let (encrypted_account, err) = read_raw_message(file_location, message_id);
    if err != 0 {
        return (vec![], err);
    }

    let nonce = GenericArray::clone_from_slice(&encrypted_account[..24]);
    let cipher = XChaCha20Poly1305::new(&key);

    let decrypted_message = match cipher.decrypt(&nonce, encrypted_account[24..].as_ref()) {
        Ok(m) => m,
        Err(_) => return (vec![], 3),
    };

    let (unpadded_message, _) = remove_padding(&decrypted_message);

    let utf8_decoded = match str::from_utf8(&unpadded_message) {
        Ok(m) => m,
        Err(_) => return (vec![], 3),
    };

    return (utf8_decoded.split("|").map(|s| s.to_string()).collect::<Vec<String>>(), 0);
}

#[repr(C)]
pub struct MessageAndError {
    message: *mut c_char,
    err: i32,
}

// Reading message specifically for interfacing with other code.
#[no_mangle]
pub extern "C" fn read_message_extern(file_location: *const c_char, key: *const c_char, message_id: usize) -> MessageAndError {
    // convert C char string to Rust string literals
    let file_location_c: &CStr = unsafe { CStr::from_ptr(file_location) };
    let file_location = match file_location_c.to_str() {
        Ok(v) => v,
        Err(_) => return MessageAndError{ message: CString::new("").unwrap().into_raw(), err: 9 },
    };
    let key_c: &CStr = unsafe { CStr::from_ptr(key) };
    let key = key_c.to_bytes();

    let key = GenericArray::clone_from_slice(&(key)[..32]);
    let (encrypted_account, err) = read_raw_message(file_location, message_id);
    if err != 0 {
        return MessageAndError{ message: CString::new("").unwrap().into_raw(), err: err as i32 };
    }

    let nonce = GenericArray::clone_from_slice(&encrypted_account[..24]);
    let cipher = XChaCha20Poly1305::new(&key);

    let decrypted_message = match cipher.decrypt(&nonce, encrypted_account[24..].as_ref()) {
        Ok(m) => m,
        Err(_) => return MessageAndError{ message: CString::new("").unwrap().into_raw(), err: 3 },
    };

    let (unpadded_message, _) = remove_padding(&decrypted_message);

    let utf8_decoded = match str::from_utf8(&unpadded_message) {
        Ok(m) => m,
        Err(_) => return MessageAndError{ message: CString::new("").unwrap().into_raw(), err: 3 },
    };

    return MessageAndError{ message: CString::new(utf8_decoded).unwrap().into_raw(), err: 0};
}

// All CStrings need to be deallocated by Rust. After using CString in another language,
// the string has to be passed to this function to avoid memory leaks.
#[no_mangle]
pub extern "C" fn deallocate_cstring(to_deallocate: *mut c_char) {
    unsafe { drop(CString::from_raw(to_deallocate)); };
}