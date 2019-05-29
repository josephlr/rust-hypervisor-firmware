// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::boot_params::BootParams;
use crate::fat;
use crate::mem::MemoryRegion;
use fat::Read;

#[derive(Debug)]
pub enum Error {
    FileError,
    KernelOld,
    MagicMissing,
    NotRelocatable,
}

impl From<fat::Error> for Error {
    fn from(_: fat::Error) -> Error {
        Error::FileError
    }
}

// Memory location where we will load our kernel
const KERNEL_LOCATION: u32 = 0x100_0000;

// Memory location where we will load our command line
const CMDLINE_START: u64 = 0x4b000;
const CMDLINE_MAX_SIZE: u64 = 0x10000;

const E820_RAM: u32 = 1;

pub fn load_initrd(f: &mut Read, params: &mut BootParams) -> Result<(), Error> {
    let mut max_load_address = params.hdr.initrd_addr_max as u64;
    if max_load_address == 0 {
        max_load_address = 0x37ff_ffff;
    }

    let e820_table = &params.e820_table[0..params.e820_entries as usize];

    // Search E820 table for highest usable ram location that is below the limit.
    let mut top_of_usable_ram = 0;
    for entry in e820_table {
        if entry.entry_type == E820_RAM {
            let m = entry.addr + entry.size - 1;
            if m > top_of_usable_ram && m < max_load_address {
                top_of_usable_ram = m;
            }
        }
    }

    if top_of_usable_ram > max_load_address {
        top_of_usable_ram = max_load_address;
    }

    let initrd_address = top_of_usable_ram - u64::from(f.get_size());
    let mut initrd_region = MemoryRegion::new(initrd_address, u64::from(f.get_size()));

    let mut offset = 0;
    while offset < f.get_size() {
        let bytes_remaining = f.get_size() - offset;

        // Use intermediate buffer for last, partial sector
        if bytes_remaining < 512 {
            let mut data: [u8; 512] = [0; 512];
            match f.read(&mut data) {
                Err(crate::fat::Error::EndOfFile) => break,
                Err(_) => return Err(Error::FileError),
                Ok(_) => {}
            }
            let dst = initrd_region.as_mut_slice(u64::from(offset), u64::from(bytes_remaining));
            dst.copy_from_slice(&data[0..bytes_remaining as usize]);
            break;
        }

        let dst = initrd_region.as_mut_slice(u64::from(offset), 512);

        match f.read(dst) {
            Err(crate::fat::Error::EndOfFile) => break,
            Err(_) => return Err(Error::FileError),
            Ok(_) => {}
        }

        offset += 512;
    }

    // initrd pointer/size
    params.hdr.ramdisk_image = initrd_address as u32;
    params.hdr.ramdisk_size = f.get_size();
    Ok(())
}

pub fn append_commandline(addition: &str, params: &mut BootParams) -> Result<(), Error> {
    let mut old_cmdline = MemoryRegion::new(
        params.hdr.cmd_line_ptr.into(),
        params.hdr.cmdline_size.into(),
    );
    let old_cmdline: &[u8] = old_cmdline.as_mut_slice(0, params.hdr.cmdline_size.into());
    let mut cmdline = MemoryRegion::new(CMDLINE_START, CMDLINE_MAX_SIZE);
    let cmdline: &mut [u8] = cmdline.as_mut_slice(0, CMDLINE_MAX_SIZE);

    // Get the length of the existing cmdline, excluding null bytes.
    let orig_len = old_cmdline
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(old_cmdline.len());
    // Copy over existing command line
    log!("Copying over {} bytes {:?}", orig_len, &old_cmdline);
    cmdline[..orig_len].copy_from_slice(&old_cmdline[..orig_len]);

    cmdline[orig_len] = b' ';
    let addition_dst = &mut cmdline[orig_len + 1..];
    addition_dst[..addition.len()].copy_from_slice(addition.as_bytes());
    addition_dst[addition.len()] = 0;

    // Command line pointer/size
    params.hdr.cmd_line_ptr = CMDLINE_START as u32;
    params.hdr.cmdline_size = (orig_len + addition.len() + 1) as u32;
    Ok(())
}

pub fn load_kernel(f: &mut Read, params: &mut BootParams) -> Result<(u64), Error> {
    f.seek(0)?;

    // TODO: Explain safety
    unsafe {
        union HeaderBuffer {
            buf: [u8; 1024],
            params: BootParams,
        }
        let mut u = HeaderBuffer { buf: [0; 1024] };
        f.read(&mut u.buf[0..512])?;
        f.read(&mut u.buf[512..])?;
        params.hdr = u.params.hdr;
    }

    if params.hdr.boot_flag != 0xAA55 {
        return Err(Error::MagicMissing);
    }

    if &params.hdr.header != b"HdrS" {
        return Err(Error::MagicMissing);
    }

    // Need for relocation
    if params.hdr.version < 0x205 {
        return Err(Error::KernelOld);
    }

    // Check relocatable
    if params.hdr.relocatable_kernel == 0 {
        return Err(Error::NotRelocatable);
    }

    // Unknown loader
    params.hdr.type_of_loader = 0xff;

    // Where we will load the kernel into
    params.hdr.code32_start = KERNEL_LOCATION;
    let mut load_offset = u64::from(KERNEL_LOCATION);

    // Skip over all the real-mode code
    let mut setup_sectors = params.hdr.setup_sects;
    if setup_sectors == 0 {
        setup_sectors = 4;
    }
    // Include the boot sector
    let protected_offset = (setup_sectors as u32 + 1) * 512;
    f.seek(protected_offset)?;

    // Load all of the remaining kernel sectors into memory
    loop {
        let mut dst = MemoryRegion::new(load_offset, 512);
        let dst = dst.as_mut_slice(0, 512);

        let result = f.read(dst);
        if result == Err(crate::fat::Error::EndOfFile) {
            break;
        }
        load_offset += result? as u64;
    }
    // 0x200 is the startup_64 offset
    return Ok(u64::from(KERNEL_LOCATION) + 0x200);
}
