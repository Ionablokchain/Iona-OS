//! Filesystem subsystem — VFS + IONAFS + procfs + devfs + FAT32
pub mod ionafs;
pub mod fat32;
pub mod vfs;
pub mod proc;
pub mod dev;

pub fn init() {
    // Initialize IONAFS (block device backed)
    ionafs::init();

    // Mount filesystems into VFS
    vfs::mount("/",     alloc::boxed::Box::new(IonafsFsAdapter));
    vfs::mount("/proc", alloc::boxed::Box::new(proc::ProcFs));
    vfs::mount("/dev",  alloc::boxed::Box::new(dev::DevFs));

    crate::serial_println!("  [VFS] mounted: / (ionafs) /proc /dev");
}

/// Adapter: wraps IONAFS as VFS FileSystem trait
struct IonafsFsAdapter;
impl vfs::FileSystem for IonafsFsAdapter {
    fn name(&self) -> &'static str { "ionafs" }
    fn read(&self, path: &str, buf: &mut [u8], _off: u64) -> vfs::Result<usize> {
        match ionafs::read(path) {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            None => Err(vfs::FsError::NotFound),
        }
    }
    fn write(&self, path: &str, buf: &[u8], _off: u64) -> vfs::Result<usize> {
        ionafs::write(path, buf);
        Ok(buf.len())
    }
    fn readdir(&self, _: &str) -> vfs::Result<alloc::vec::Vec<alloc::string::String>> {
        Ok(ionafs::list())
    }
    fn stat(&self, path: &str) -> vfs::Result<vfs::Stat> {
        if ionafs::exists(path) {
            Ok(vfs::Stat { size: 0, is_dir: false, is_file: true, mode: 0o644 })
        } else {
            Err(vfs::FsError::NotFound)
        }
    }
    fn create(&self, path: &str) -> vfs::Result<()> { ionafs::write(path, &[]); Ok(()) }
    fn remove(&self, _: &str) -> vfs::Result<()>    { Ok(()) }
}
