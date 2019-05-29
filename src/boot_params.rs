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

use core::mem;

const EDD_MBR_SIG_MAX: usize = 16;
const E820_MAX_ENTRIES_ZEROPAGE: usize = 128;
const EDDMAXNR: usize = 6;

#[derive(Copy)]
#[repr(packed(2))]
pub struct Align2<T>(pub T);

impl<T: Copy> Clone for Align2<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SetupHeader {
    _pad6: [u8; 1],
    pub setup_sects: u8,
    #[deprecated]
    pub root_flags: u16,
    #[deprecated]
    pub syssize: u32,
    #[deprecated]
    pub ram_size: u16,
    pub vid_mode: u16,
    #[deprecated]
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: [u8; 2],
    pub header: [u8; 4],
    pub version: u16,
    pub realmode_swtch: u32,
    #[deprecated]
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    #[deprecated]
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BootParams {
    pub screen_info: ScreenInfo,
    pub apm_bios_info: ApmBiosInfo,
    _pad2: [u8; 4],
    pub tboot_addr: *const (),
    pub ist_info: IstInfo,
    pub acpi_rsdp_addr: *const (),
    _pad3: [u8; 8],
    #[deprecated]
    pub hd0_info: HdInfo,
    #[deprecated]
    pub hd1_info: HdInfo,
    #[deprecated]
    pub sys_desc_table: SysDescTable,
    pub olpc_ofw_header: OlpcOfwHeader,
    pub ext_ramdisk_image: u32,
    pub ext_ramdisk_size: u32,
    pub ext_cmd_line_ptr: u32,
    _pad4: [u8; 116],
    pub edid_info: EdidInfo,
    pub efi_info: EfiInfo,
    pub alt_mem_k: u32,
    pub scratch: u32,
    pub e820_entries: u8,
    pub eddbuf_entries: u8,
    pub edd_mbr_sig_buf_entries: u8,
    pub kbd_status: u8,
    pub secure_boot: u8,
    _pad5: [u8; 2],
    pub sentinel: u8,
    pub hdr: SetupHeader,
    _pad7: [u8; (0x290 - 0x1f0 - mem::size_of::<SetupHeader>())],
    pub edd_mbr_sig_buffer: [u32; EDD_MBR_SIG_MAX],
    pub e820_table: [E820Entry; E820_MAX_ENTRIES_ZEROPAGE],
    _pad8: [u8; 48],
    pub eddbuf: [EddInfo; EDDMAXNR],
    _pad9: [u8; 276],
}

#[derive(Clone, Copy)]
#[repr(C, packed(4))] // packed needed as struct size is not a multiple of 8
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SizePos {
    pub size: u8,
    pub pos: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ScreenInfo {
    pub orig_x: u8,
    pub orig_y: u8,
    pub ext_mem_k: u16,
    pub orig_video_page: u16,
    pub orig_video_mode: u8,
    pub orig_video_cols: u8,
    pub flags: u8,
    unused2: u8,
    pub orig_video_ega_bx: u16,
    unused3: u16,
    pub orig_video_lines: u8,
    pub orig_video_is_vga: u8,
    pub orig_video_points: u16,

    /* VESA graphic mode -- linear frame buffer */
    pub lfb_width: u16,
    pub lfb_height: u16,
    pub lfb_depth: u16,
    pub lfb_base: u32,
    pub lfb_size: u32,
    pub cl_magic: u16,
    pub cl_offset: u16,
    pub lfb_linelength: u16,
    pub red: SizePos,
    pub green: SizePos,
    pub blue: SizePos,
    pub rsvd: SizePos,
    pub vesapm_seg: u16,
    pub vesapm_off: u16,
    pub pages: u16,
    pub vesa_attributes: u16,
    pub capabilities: Align2<u32>,
    pub ext_lfb_base: Align2<u32>,
    _reserved: [u8; 2],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ApmBiosInfo {
    pub version: u16,
    pub cseg: u16,
    pub offset: u32,
    pub cseg_16: u16,
    pub dseg: u16,
    pub flags: u16,
    pub cseg_len: u16,
    pub cseg_16_len: u16,
    pub dseg_len: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IstInfo {
    pub signature: u32,
    pub command: u32,
    pub event: u32,
    pub perf_level: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct HdInfo([u8; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SysDescTable {
    length: u16,
    table: [u8; 14],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OlpcOfwHeader {
    ofw_magic: u32, /* OFW signature */
    ofw_version: u32,
    cif_handler: u32, /* callback into OFW */
    irq_desc_table: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct EfiInfo {
    pub loader_signature: u32,
    pub systab: u32,
    pub memdesc_size: u32,
    pub memdesc_version: u32,
    pub memmap: u32,
    pub memmap_size: u32,
    pub systab_hi: u32,
    pub memmap_hi: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct EdidInfo([u8; 128]); // TODO

#[derive(Clone, Copy)]
#[repr(C)]
pub struct EddInfo([u8; 0x52]); // TODO

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<ScreenInfo>(), 0x40);
        assert_eq!(mem::size_of::<ApmBiosInfo>(), 0x14);
        assert_eq!(mem::size_of::<IstInfo>(), 0x10);
        assert_eq!(mem::size_of::<SysDescTable>(), 0x10);
        assert_eq!(mem::size_of::<OlpcOfwHeader>(), 0x10);
        assert_eq!(mem::size_of::<EdidInfo>(), 0x80);
        assert_eq!(mem::size_of::<EfiInfo>(), 0x20);
        assert_eq!(mem::size_of::<E820Entry>(), 0x14);
        assert_eq!(mem::size_of::<BootParams>(), 0x1000);
    }

    #[test]
    fn test_struct_alignment() {
        assert_eq!(mem::align_of::<SetupHeader>(), 8);
        assert_eq!(mem::align_of::<BootParams>(), 8);
        assert_eq!(mem::align_of::<ScreenInfo>(), 4);
        assert_eq!(mem::align_of::<E820Entry>(), 4);
    }

    #[test]
    fn test_offsets() {
        let buf = [0u8; 0x1000];
        let ptr = &buf[0] as *const _ as *const BootParams;
        let params = unsafe { &*ptr };
        assert_eq!(
            &params.hdr.setup_sects as *const _ as usize - ptr as usize,
            0x1f1
        );
        assert_eq!(
            &params.hdr.header[0] as *const _ as usize - ptr as usize,
            0x202
        );
    }

    #[test]
    fn test_e820_access() {
        let arr: [E820Entry; 2] = [
            E820Entry {
                addr: 0,
                size: 1,
                entry_type: 2,
            },
            E820Entry {
                addr: 3,
                size: 4,
                entry_type: 5,
            },
        ];
        assert_eq!(mem::align_of::<E820Entry>(), 4);

        // Accessing a u32 field is safe
        let v32 = arr[0].entry_type;
        assert_eq!(v32, 2);
        // Referencing a u32 field _should_ be safe (but is not)
        let r32 = unsafe { &arr[1].entry_type };
        assert_eq!(*r32, 5);

        // Accessing a u64 field is safe
        let v64 = arr[0].addr;
        assert_eq!(v64, 0);
        // Referencing a u64 field is unsafe
        let r64 = unsafe { &arr[1].addr };
        assert_eq!(*r64, 3);
    }
}
