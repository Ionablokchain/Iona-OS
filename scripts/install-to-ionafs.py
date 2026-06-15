#!/usr/bin/env python3
"""
IONA OS — Install binaries into IONAFS disk image

Usage:
    python3 scripts/install-to-ionafs.py \
        --disk dist/iona-disk.img \
        --file target/.../iona-node \
        --path /bin/iona-node

IONAFS Layout (sectors of 512 bytes):
    LBA 0:      Superblock (magic=0x494F4E41 "IONA", num_files, journal_head)
    LBA 1-15:   File index (120 entries × 64 bytes)
    LBA 16-63:  WAL journal (reserved)
    LBA 64+:    File data

File index entry (64 bytes):
    [0..32]  path (null-terminated)
    [32..40] lba  (u64 le)
    [40..48] size (u64 le)
    [48..56] flags (u64 le): 0=empty, 1=file, 2=deleted
    [56..64] reserved

This script is idempotent: if the file already exists, it is overwritten.
If the new file fits in the same LBA range as the old one, space is reused.
Otherwise, a new LBA is allocated at the end of the data area.
"""

import argparse
import logging
import os
import struct
import sys
from pathlib import Path
from typing import List, Tuple, Optional

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
SECTOR_SIZE = 512
MAGIC = 0x494F4E41  # "IONA"
MAGIC_BYTES = struct.pack('<I', MAGIC)

# LBA addresses
SUPERBLOCK_LBA = 0
INDEX_START_LBA = 1
INDEX_SECTORS = 15
DATA_START_LBA = 64

# Index entries
ENTRIES_PER_INDEX = (INDEX_SECTORS * SECTOR_SIZE) // 64  # 120
ENTRY_SIZE = 64

# Max file size (1 GiB) to prevent memory overflow
MAX_FILE_SIZE = 1024 * 1024 * 1024

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )


# -----------------------------------------------------------------------------
# IONAFS structures
# -----------------------------------------------------------------------------
class Superblock:
    """IONAFS superblock."""
    __slots__ = ('magic', 'num_files', 'journal_head')

    def __init__(self, magic: int, num_files: int, journal_head: int):
        self.magic = magic
        self.num_files = num_files
        self.journal_head = journal_head

    @classmethod
    def read(cls, fp) -> 'Superblock':
        """Read superblock from file at LBA 0."""
        fp.seek(SUPERBLOCK_LBA * SECTOR_SIZE)
        data = fp.read(SECTOR_SIZE)
        if len(data) < SECTOR_SIZE:
            raise IOError("Disk image too small to contain superblock")
        magic, num_files, journal_head = struct.unpack_from('<III', data, 0)
        return cls(magic, num_files, journal_head)

    def write(self, fp) -> None:
        """Write superblock to file at LBA 0."""
        data = bytearray(SECTOR_SIZE)
        struct.pack_into('<III', data, 0, self.magic, self.num_files, self.journal_head)
        fp.seek(SUPERBLOCK_LBA * SECTOR_SIZE)
        fp.write(data)
        fp.flush()


class IndexEntry:
    """Single entry in the file index."""
    __slots__ = ('path', 'lba', 'size', 'flags')

    def __init__(self, path: str, lba: int, size: int, flags: int):
        self.path = path
        self.lba = lba
        self.size = size
        self.flags = flags

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> 'IndexEntry':
        """Parse an entry from raw bytes at given offset."""
        path_bytes = data[offset:offset + 32]
        path = path_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        lba, size, flags = struct.unpack_from('<QQQ', data, offset + 32)
        return cls(path, lba, size, flags)

    def to_bytes(self) -> bytes:
        """Serialize entry to 64 bytes."""
        data = bytearray(ENTRY_SIZE)
        path_bytes = self.path.encode('utf-8')[:31]
        data[:len(path_bytes)] = path_bytes
        struct.pack_into('<QQQ', data, 32, self.lba, self.size, self.flags)
        return bytes(data)

    @property
    def is_valid(self) -> bool:
        return self.flags == 1

    @property
    def is_empty(self) -> bool:
        return self.flags == 0


class Index:
    """Collection of index entries."""
    def __init__(self, entries: List[IndexEntry]):
        self.entries = entries

    @classmethod
    def read(cls, fp) -> 'Index':
        """Read the entire index from disk."""
        fp.seek(INDEX_START_LBA * SECTOR_SIZE)
        raw = fp.read(INDEX_SECTORS * SECTOR_SIZE)
        if len(raw) < INDEX_SECTORS * SECTOR_SIZE:
            raise IOError("Disk image too small to contain index")

        entries = []
        for i in range(ENTRIES_PER_INDEX):
            offset = i * ENTRY_SIZE
            entries.append(IndexEntry.from_bytes(raw, offset))
        return cls(entries)

    def write(self, fp) -> None:
        """Write the entire index to disk."""
        data = bytearray(INDEX_SECTORS * SECTOR_SIZE)
        for i, entry in enumerate(self.entries):
            offset = i * ENTRY_SIZE
            data[offset:offset + ENTRY_SIZE] = entry.to_bytes()
        fp.seek(INDEX_START_LBA * SECTOR_SIZE)
        fp.write(data)
        fp.flush()

    def find_by_path(self, path: str) -> Tuple[Optional[int], Optional[IndexEntry]]:
        """Return (index, entry) for given path, or (None, None) if not found."""
        for i, entry in enumerate(self.entries):
            if entry.path == path and entry.is_valid:
                return i, entry
        return None, None

    def find_free_slot(self) -> Optional[int]:
        """Return index of first empty slot, or None if full."""
        for i, entry in enumerate(self.entries):
            if entry.is_empty:
                return i
        return None

    def set_entry(self, idx: int, entry: IndexEntry) -> None:
        """Replace an entry at given index."""
        self.entries[idx] = entry

    @property
    def valid_count(self) -> int:
        """Number of valid (non‑empty) entries."""
        return sum(1 for e in self.entries if e.is_valid)


# -----------------------------------------------------------------------------
# Disk utilities
# -----------------------------------------------------------------------------
def get_data_end_lba(entries: List[IndexEntry]) -> int:
    """
    Calculate the highest LBA used by any file in the data area.
    Returns DATA_START_LBA if no files exist.
    """
    max_lba = DATA_START_LBA
    for entry in entries:
        if not entry.is_valid:
            continue
        if entry.lba < DATA_START_LBA:
            # In case of corrupted index, ignore
            continue
        end_lba = entry.lba + (entry.size + SECTOR_SIZE - 1) // SECTOR_SIZE
        if end_lba > max_lba:
            max_lba = end_lba
    return max_lba


def calculate_needed_sectors(file_size: int) -> int:
    """Return number of sectors required to store a file."""
    return (file_size + SECTOR_SIZE - 1) // SECTOR_SIZE


def fits_in_place(old_size: int, new_size: int) -> bool:
    """Check if new file can fit in the space previously occupied by old file."""
    old_sectors = calculate_needed_sectors(old_size)
    new_sectors = calculate_needed_sectors(new_size)
    return new_sectors <= old_sectors


def write_file_data(fp, lba: int, data: bytes) -> None:
    """Write file data at given LBA, padded to sector boundary."""
    pad_len = (SECTOR_SIZE - len(data) % SECTOR_SIZE) % SECTOR_SIZE
    padded = data + b'\x00' * pad_len
    fp.seek(lba * SECTOR_SIZE)
    fp.write(padded)
    fp.flush()


def read_file_data(fp, lba: int, size: int) -> bytes:
    """Read file data from given LBA, truncating to exact size."""
    sectors = (size + SECTOR_SIZE - 1) // SECTOR_SIZE
    fp.seek(lba * SECTOR_SIZE)
    data = fp.read(sectors * SECTOR_SIZE)
    return data[:size]


def initialize_disk(fp, force: bool) -> None:
    """Initialize a blank IONAFS disk with empty superblock and index."""
    if not force:
        raise RuntimeError("Disk not initialized (missing IONAFS superblock). Use --force to initialize.")
    logger.info("Initializing new IONAFS filesystem on disk")
    superblock = Superblock(magic=MAGIC, num_files=0, journal_head=0)
    superblock.write(fp)
    # Create empty index
    entries = [IndexEntry("", 0, 0, 0) for _ in range(ENTRIES_PER_INDEX)]
    index = Index(entries)
    index.write(fp)
    logger.debug("Initialization complete")


# -----------------------------------------------------------------------------
# Main installation logic
# -----------------------------------------------------------------------------
def install_file(disk_path: Path, file_path: Path, target_path: str, dry_run: bool, force: bool) -> None:
    """Install a single file into the IONAFS disk image."""
    if not disk_path.exists():
        raise FileNotFoundError(f"Disk image not found: {disk_path}")
    if not file_path.exists():
        raise FileNotFoundError(f"Source file not found: {file_path}")

    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({file_size} bytes). Maximum allowed: {MAX_FILE_SIZE} bytes")

    logger.info("Installing %s (%d bytes) -> %s", target_path, file_size, disk_path)

    # Read file content only if not dry-run
    file_data = None
    if not dry_run:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            if len(file_data) != file_size:
                raise IOError(f"Read {len(file_data)} bytes, expected {file_size}")

    # Open disk image (read-write if not dry-run)
    mode = 'r+b' if not dry_run else 'rb'
    with open(disk_path, mode) as fp:
        # Read superblock
        try:
            superblock = Superblock.read(fp)
        except (struct.error, IOError) as e:
            logger.error("Failed to read superblock: %s", e)
            if not dry_run:
                initialize_disk(fp, force)
                superblock = Superblock.read(fp)
            else:
                raise

        if superblock.magic != MAGIC:
            logger.warning("Superblock magic mismatch: 0x%08X", superblock.magic)
            if not dry_run:
                initialize_disk(fp, force)
                superblock = Superblock.read(fp)
            else:
                raise RuntimeError("Invalid superblock magic (use --force to initialize)")

        # Read index
        index = Index.read(fp)
        old_idx, old_entry = index.find_by_path(target_path)

        if dry_run:
            # Simulate: find free slot, compute new LBA
            if old_entry:
                logger.info("DRY RUN: Would overwrite existing file at LBA %d (size %d)", old_entry.lba, old_entry.size)
                if fits_in_place(old_entry.size, file_size):
                    logger.info("DRY RUN: New file fits in same space")
                else:
                    new_lba = get_data_end_lba(index.entries)
                    logger.info("DRY RUN: New file needs larger space, would allocate LBA %d", new_lba)
            else:
                slot = index.find_free_slot()
                if slot is None:
                    raise RuntimeError("Index full (max 120 files)")
                new_lba = get_data_end_lba(index.entries)
                logger.info("DRY RUN: Would add new file at slot %d, LBA %d", slot, new_lba)
            return

        # Actual write
        # Determine LBA to use
        if old_entry:
            # Overwrite existing entry
            idx = old_idx
            if fits_in_place(old_entry.size, file_size):
                data_lba = old_entry.lba
            else:
                data_lba = get_data_end_lba(index.entries)
            new_entry = IndexEntry(target_path, data_lba, file_size, 1)
        else:
            # New entry
            slot = index.find_free_slot()
            if slot is None:
                raise RuntimeError("Index full (max 120 files). Cannot add new file.")
            data_lba = get_data_end_lba(index.entries)
            new_entry = IndexEntry(target_path, data_lba, file_size, 1)
            idx = slot
            superblock.num_files += 1

        # Write file data
        write_file_data(fp, data_lba, file_data)

        # Update index
        index.set_entry(idx, new_entry)
        index.write(fp)

        # Update superblock
        superblock.write(fp)

        logger.info("Successfully installed %s (LBA %d, %d bytes)", target_path, data_lba, file_size)


# -----------------------------------------------------------------------------
# Command-line interface
# -----------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a binary into an IONAFS disk image",
        epilog="The disk image must already contain a valid IONAFS superblock, "
               "or use --force to initialize a new filesystem."
    )
    parser.add_argument('--disk', required=True, help='Path to the disk image')
    parser.add_argument('--file', required=True, help='Source file to install')
    parser.add_argument('--path', required=True, help='Destination path inside IONAFS (e.g., /bin/iona-node)')
    parser.add_argument('--verbose', action='store_true', help='Enable debug output')
    parser.add_argument('--dry-run', action='store_true', help='Simulate installation without modifying disk')
    parser.add_argument('--force', action='store_true', help='Force initialization of disk if superblock missing')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    disk_path = Path(args.disk)
    file_path = Path(args.file)
    target_path = args.path

    try:
        install_file(disk_path, file_path, target_path, args.dry_run, args.force)
    except Exception as e:
        logger.error("Installation failed: %s", e)
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
