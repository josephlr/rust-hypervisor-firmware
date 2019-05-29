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

#![feature(asm, global_asm)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports))]

#[macro_use]
mod logger;

use core::panic::PanicInfo;

use cpuio::Port;

mod block;
mod boot_params;
#[cfg(not(test))]
mod bzimage;
mod fat;
mod loader;
mod mem;
mod mmio;
mod part;
mod pci;
mod virtio;

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
/// Reset the VM via the keyboard controller
fn i8042_reset() -> ! {
    loop {
        let mut good: u8 = 0x02;
        let mut i8042_command: Port<u8> = unsafe { Port::new(0x64) };
        while good & 0x02 > 0 {
            good = i8042_command.read();
        }
        i8042_command.write(0xFE);
    }
}

#[cfg(not(test))]
/// Setup page tables to provide an identity mapping over the full 4GiB range
fn setup_pagetables() {
    const ADDRESS_SPACE_GIB: u64 = 64;
    let pte = mem::MemoryRegion::new(0xb000, 512 * ADDRESS_SPACE_GIB * 8);
    for i in 0..(512 * ADDRESS_SPACE_GIB) {
        pte.io_write_u64(i * 8, (i << 21) + 0x83u64)
    }

    let pde = mem::MemoryRegion::new(0xa000, 4096);
    for i in 0..ADDRESS_SPACE_GIB {
        pde.io_write_u64(i * 8, (0xb000u64 + (0x1000u64 * i)) | 0x03);
    }

    x86_64::instructions::tlb::flush_all();
    log!("Page tables setup\n");
}

#[cfg(not(test))]
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
#[cfg(not(test))]
const VIRTIO_PCI_BLOCK_DEVICE_ID: u16 = 0x1042;

#[cfg(not(test))]
global_asm!(
    r#".global _start
_start:
    .intel_syntax noprefix
    mov rsp, 0x180000
    jmp start64
"#
);

#[cfg(not(test))]
type LinuxEntry64 = extern "C" fn(usize, &mut boot_params::BootParams) -> !;

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn start64(_: usize, params: &mut boot_params::BootParams) -> ! {
    log!("Starting..\n");
    log!("Stack: {:p}\n", &params as *const _);
    log!("CmdLine Start: {:x}\n", params.hdr.cmd_line_ptr);
    log!("CmdLine Max Size: {:x}\n", params.hdr.cmdline_size);
    let mut old_cmdline = crate::mem::MemoryRegion::new(
        params.hdr.cmd_line_ptr.into(),
        params.hdr.cmdline_size.into(),
    );
    let old_cmdline: &[u8] = old_cmdline.as_mut_slice(0, params.hdr.cmdline_size.into());
    log!(
        "0 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    x86_64::instructions::tlb::flush_all();

    log!(
        "0.5 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    setup_pagetables();

    log!(
        "1 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    pci::print_bus();

    log!(
        "2 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    let mut pci_transport;
    let mut mmio_transport;

    let mut device = if let Some(pci_device) =
        pci::search_bus(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_BLOCK_DEVICE_ID)
    {
        pci_transport = pci::VirtioPciTransport::new(pci_device);
        block::VirtioBlockDevice::new(&mut pci_transport)
    } else {
        mmio_transport = mmio::VirtioMMIOTransport::new(0xd000_0000u64);
        block::VirtioBlockDevice::new(&mut mmio_transport)
    };
    log!(
        "3 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    device.init().unwrap_or_else(|e| {
        log!("Error configuring block device: {:?}\n", e);
        i8042_reset()
    });
    log!(
        "4 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    let (start, end) = part::find_efi_partition(&device).unwrap_or_else(|e| {
        log!("Failed to find EFI partition: {:?}\n", e);
        i8042_reset()
    });
    log!("Found EFI partition\n");
    log!(
        "5 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    let mut f = fat::Filesystem::new(&device, start, end);
    f.init().unwrap_or_else(|e| {
        log!("Failed to create filesystem: {:?}\n", e);
        i8042_reset()
    });
    log!("Filesystem ready\n");
    log!(
        "6 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    let jump_address = loader::load_default_entry(&f, params).unwrap_or_else(|e| {
        log!("Error loading default entry: {:?}\n", e);
        i8042_reset()
    });
    log!(
        "7 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    device.reset();
    log!(
        "8 Copying over bytes at {:p}: {:?}\n",
        &old_cmdline[0] as *const _,
        &old_cmdline
    );

    log!("Jumping to kernel\n");

    // Rely on x86 C calling convention where second argument is put into %rsi register
    let code: LinuxEntry64 = unsafe { core::mem::transmute(jump_address) };
    (code)(0 /* dummy value */, params);
}
