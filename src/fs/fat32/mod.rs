//! FAT32 filesystem — citit-only pentru Faza 3
//! Folosit pentru a citi kernel-ul și modulele din disk image la boot.

use alloc::vec::Vec;

const SECTOR_SIZE: usize = 512;

pub struct Fat32 {
    pub sectors_per_cluster: u8,
    pub reserved_sectors:    u16,
    pub num_fats:            u8,
    pub fat_size_sectors:    u32,
    pub root_cluster:        u32,
    pub total_sectors:       u32,
}

impl Fat32 {
    /// Parsează BPB (BIOS Parameter Block) din boot sector
    pub fn from_boot_sector(sector: &[u8; 512]) -> Option<Self> {
        if sector[510] != 0x55 || sector[511] != 0xAA { return None; }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector != 512 { return None; } // simplificare

        Some(Fat32 {
            sectors_per_cluster: sector[13],
            reserved_sectors:    u16::from_le_bytes([sector[14], sector[15]]),
            num_fats:            sector[16],
            fat_size_sectors:    u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]),
            root_cluster:        u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]),
            total_sectors:       u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]),
        })
    }

    pub fn fat_start_lba(&self)  -> u64 { self.reserved_sectors as u64 }
    pub fn data_start_lba(&self) -> u64 {
        self.fat_start_lba() + self.num_fats as u64 * self.fat_size_sectors as u64
    }

    pub fn cluster_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba() + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }

    /// Citește un cluster de pe disc
    pub fn read_cluster(&self, cluster: u32) -> Vec<u8> {
        let lba = self.cluster_lba(cluster);
        let n   = self.sectors_per_cluster as usize;
        let mut buf = alloc::vec![0u8; n * SECTOR_SIZE];
        for i in 0..n {
            crate::drivers::virtio::blk::read_sectors(lba + i as u64, 1, &mut buf[i*512..(i+1)*512]);
        }
        buf
    }

    /// Urmărește lanțul FAT pentru un cluster
    pub fn next_cluster(&self, cluster: u32) -> Option<u32> {
        let fat_offset = cluster * 4;
        let fat_sector = self.fat_start_lba() + (fat_offset / 512) as u64;
        let mut buf = [0u8; 512];
        crate::drivers::virtio::blk::read_sectors(fat_sector, 1, &mut buf);
        let next = u32::from_le_bytes(buf[(fat_offset % 512) as usize..][..4].try_into().unwrap_or([0;4])) & 0x0FFF_FFFF;
        if next >= 0x0FFF_FFF8 { None } else { Some(next) }
    }
}
