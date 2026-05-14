#!/usr/bin/env python3
"""
IONA OS — Install binaries into IONAFS disk image
Usage:
    python3 scripts/install-to-ionafs.py \
        --disk dist/iona-disk.img \
        --file target/.../iona-node \
        --path /bin/iona-node

IONAFS Layout (sectors of 512 bytes):
    LBA 0:      Superblock  (magic=0x494F4E41 "IONA", num_files, journal_head)
    LBA 1-15:   File index  (120 entries × 64 bytes)
    LBA 16-63:  WAL journal
    LBA 64+:    File data

File index entry (64 bytes):
    [0..32]  path (null-terminated)
    [32..40] lba  (u64 le)
    [40..48] size (u64 le)
    [48..56] flags (u64 le): 0=empty, 1=file, 2=deleted
    [56..64] reserved
"""

import argparse, struct, sys, os

SECTOR   = 512
MAGIC    = 0x494F4E41  # "IONA"
IDX_LBA  = 1
IDX_SECTORS = 15
IDX_ENTRIES = (IDX_SECTORS * SECTOR) // 64   # 120 entries
DATA_LBA = 64

def read_sector(fp, lba, n=1):
    fp.seek(lba * SECTOR)
    return fp.read(n * SECTOR)

def write_sector(fp, lba, data):
    assert len(data) % SECTOR == 0
    fp.seek(lba * SECTOR)
    fp.write(data)

def read_superblock(fp):
    raw = read_sector(fp, 0)
    magic, num_files, journal_head = struct.unpack_from('<III', raw, 0)
    return magic, num_files, journal_head

def write_superblock(fp, num_files, journal_head=0):
    raw = bytearray(SECTOR)
    struct.pack_into('<III', raw, 0, MAGIC, num_files, journal_head)
    write_sector(fp, 0, bytes(raw))

def read_index(fp):
    """Returns list of (path_bytes, lba, size, flags) tuples."""
    raw = read_sector(fp, IDX_LBA, IDX_SECTORS)
    entries = []
    for i in range(IDX_ENTRIES):
        off = i * 64
        path_raw = raw[off:off+32]
        lba, size, flags = struct.unpack_from('<QQQ', raw, off+32)
        path = path_raw.split(b'\x00')[0].decode('utf-8', errors='replace')
        entries.append((path, lba, size, flags))
    return entries

def write_index(fp, entries):
    raw = bytearray(IDX_SECTORS * SECTOR)
    for i, (path, lba, size, flags) in enumerate(entries[:IDX_ENTRIES]):
        off = i * 64
        pb = path.encode('utf-8')[:31]
        raw[off:off+len(pb)] = pb
        struct.pack_into('<QQQ', raw, off+32, lba, size, flags)
    write_sector(fp, IDX_LBA, bytes(raw))

def find_free_data_lba(entries, file_size):
    """Find next free LBA after all existing files."""
    max_lba = DATA_LBA
    for path, lba, size, flags in entries:
        if flags == 1 and lba >= DATA_LBA:
            end = lba + (size + SECTOR - 1) // SECTOR
            if end > max_lba:
                max_lba = end
    return max_lba

def install_file(disk_path, file_path, ionafs_path):
    file_data = open(file_path, 'rb').read()
    file_size = len(file_data)
    print(f"  Installing {ionafs_path} ({file_size:,} bytes)")

    with open(disk_path, 'r+b') as fp:
        magic, num_files, jhead = read_superblock(fp)
        if magic != MAGIC:
            print(f"  Init fresh IONAFS superblock (was 0x{magic:08x})")
            write_superblock(fp, 0)
            num_files = 0

        entries = read_index(fp)

        # Check if path already exists → overwrite
        existing = None
        for i, (p, lba, size, flags) in enumerate(entries):
            if p == ionafs_path and flags == 1:
                existing = i
                break

        if existing is not None:
            # Overwrite: reuse LBA if size fits, else allocate new
            old_lba = entries[existing][1]
            old_sectors = (entries[existing][2] + SECTOR - 1) // SECTOR
            new_sectors = (file_size + SECTOR - 1) // SECTOR
            if new_sectors <= old_sectors:
                data_lba = old_lba
            else:
                data_lba = find_free_data_lba(entries, file_size)
            entries[existing] = (ionafs_path, data_lba, file_size, 1)
            print(f"  Overwriting existing entry at idx={existing} lba={data_lba}")
        else:
            # New entry
            slot = next((i for i, (p,l,s,f) in enumerate(entries) if f != 1), None)
            if slot is None:
                print("ERROR: IONAFS index full (120 files)")
                sys.exit(1)
            data_lba = find_free_data_lba(entries, file_size)
            entries[slot] = (ionafs_path, data_lba, file_size, 1)
            num_files += 1
            print(f"  New entry at idx={slot} lba={data_lba}")

        # Write file data (padded to sector boundary)
        padded = file_data + b'\x00' * (SECTOR - file_size % SECTOR) if file_size % SECTOR else file_data
        write_sector(fp, data_lba, padded)
        write_index(fp, entries)
        write_superblock(fp, num_files, jhead)

    print(f"  Done. Disk {disk_path}: {ionafs_path} installed.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--disk',  required=True)
    ap.add_argument('--file',  required=True)
    ap.add_argument('--path',  required=True)
    args = ap.parse_args()
    if not os.path.exists(args.disk):
        print(f"ERROR: disk image not found: {args.disk}")
        sys.exit(1)
    if not os.path.exists(args.file):
        print(f"ERROR: file not found: {args.file}")
        sys.exit(1)
    install_file(args.disk, args.file, args.path)

if __name__ == '__main__':
    main()
