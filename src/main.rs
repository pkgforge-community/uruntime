use std::{
    path::PathBuf,
    thread::{sleep, spawn},
    process::{exit, Command},
    time::{Instant, Duration},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{symlink, MetadataExt},
    {env::{self, current_exe}, fs, time},
    io::{ErrorKind::NotFound, Error, Result},
    fs::{create_dir, create_dir_all, read_to_string, remove_dir, remove_file, File},
};

use which::which;
use cfg_if::cfg_if;
use goblin::elf::Elf;
use memfd_exec::{MemFdExecutable, Stdio};
use nix::sys::{wait::waitpid, signal::{Signal, kill}};
use nix::unistd::{access, fork, getcwd, AccessFlags, ForkResult, Pid};
use signal_hook::{consts::{SIGINT, SIGTERM, SIGQUIT, SIGHUP}, iterator::Signals};

#[cfg(feature = "pie-ulexec")]
mod pie_ulexec {
    pub use goblin::elf::program_header;
    pub use nix::unistd::{close, write};
    pub use std::{os::fd::AsRawFd, ffi::CString};
    pub use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
}
#[cfg(feature = "pie-ulexec")]
use pie_ulexec::*;

#[derive(Debug)]
struct Embed {
    #[cfg(feature = "squashfs")]
    squashfuse: Vec<u8>,
    #[cfg(feature = "squashfs")]
    unsquashfs: Vec<u8>,
    #[cfg(feature = "dwarfs")]
    dwarfs_universal: Vec<u8>,
}

impl Default for Embed {
    fn default() -> Self {
        Embed {
            #[cfg(feature = "squashfs")]
            unsquashfs: include_bytes!("../assets/unsquashfs-upx").to_vec(),
            #[cfg(feature = "squashfs")]
            squashfuse: include_bytes!("../assets/squashfuse-upx").to_vec(),
            #[cfg(feature = "dwarfs")]
            dwarfs_universal: include_bytes!("../assets/dwarfs-universal-upx").to_vec(),
        }
    }
}

#[derive(Debug)]
struct Image {
    path: PathBuf,
    offset: u64,
    is_squash: bool,
    is_dwar: bool,
}


fn get_image(path: &PathBuf, offset: u64) -> Result<Image> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 4];
    file.seek(SeekFrom::Start(offset))?;
    let bytes_read = file.read(&mut buffer)?;
    let mut result = Image {
        path: path.to_path_buf(),
        offset,
        is_dwar: false,
        is_squash: false
    };
    if bytes_read == 4 {
        let read_str = String::from_utf8_lossy(&buffer);
        if read_str.contains("DWAR") {
            result.is_dwar = true
        } else if read_str.contains("hsqs") {
            result.is_squash = true
        }
    }
    if !result.is_squash && !result.is_dwar {
        return Err(Error::new(NotFound, "SquashFS or DwarFS image not found!"))
    }
    Ok(result)
}

fn get_env_var(env_var: &str) -> String {
    let mut ret = "".to_string();
    if let Ok(res) = env::var(env_var) { ret = res };
    return ret
}

fn add_to_path(dir: &PathBuf) {
    let old_path = get_env_var("PATH");
    if old_path.is_empty() {
        env::set_var("PATH", dir)
    } else {
        env::set_var("PATH", format!("{old_path}:{}", dir.display()))
    }
}

fn check_fuse() {
    let mut is_fusermount = true;
    let tmp_path_dir = &PathBuf::from("/tmp/.path");
    if tmp_path_dir.is_dir() {
        add_to_path(tmp_path_dir)
    }
    for fusermount in vec!["fusermount", "fusermount3"] {
        let fallback: &str;
        if fusermount.ends_with("3") {
            fallback = "fusermount"
        } else {
            fallback = "fusermount3"
        }
        if which(fusermount).is_err() {
            if let Ok(fusermount_path) = which(fallback) {
                if !tmp_path_dir.is_dir() {
                    if let Err(err) = create_dir_all(tmp_path_dir) {
                        eprintln!("Failed to create fusermount fallback dir: {err}: {:?}", tmp_path_dir);
                        break
                    }
                }
                let fsmntlink_path = &format!("{}/{fusermount}", tmp_path_dir.display());
                let _ = remove_file(fsmntlink_path);
                if let Err(err) = symlink(fusermount_path, fsmntlink_path) {
                    eprintln!("Failed to create fusermount fallback symlink: {err}: {fsmntlink_path}");
                    break
                }
                add_to_path(tmp_path_dir);
                break
            } else {
                is_fusermount = false
            }
        }
    }
    if access("/dev/fuse", AccessFlags::R_OK).is_err() ||
       access("/dev/fuse", AccessFlags::W_OK).is_err() || !is_fusermount {
        eprintln!("{}: failed to utilize FUSE during startup", std::env::args().next().unwrap());
        cfg_if!{
            if #[cfg(feature = "appimage")] {
                let arg_pfx = "appimage";
                let self_name = "AppImage";
            } else {
                let arg_pfx = "runtime";
                let self_name = "RunImage";
            }
        }
        let title = format!("Cannot mount {self_name}, please check your FUSE setup.\n");
        let body = strip_str(&format!("
            You might still be able to extract the contents of this {self_name}
            if you run it with the --{arg_pfx}-extract option
            See https://github.com/AppImage/AppImageKit/wiki/FUSE
            for more information
        "));
        eprintln!("{title}{body}");
        exit(1)
    }
}

#[cfg(feature = "pie-ulexec")]
fn is_pie(bytes: &Vec<u8>) -> bool {
    let elf = Elf::parse(&bytes).unwrap();
    elf.program_headers.iter()
        .find(|h| h.p_type == program_header::PT_LOAD)
        .unwrap()
    .p_vaddr == 0
}

fn get_runtime_size(path: &PathBuf) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut elf_header_raw = [0; 64];
    file.read_exact(&mut elf_header_raw)?;
    let section_table_offset = u64::from_le_bytes(elf_header_raw[40..48].try_into().unwrap()); // e_shoff
    let section_count = u16::from_le_bytes(elf_header_raw[60..62].try_into().unwrap()); // e_shnum
    let section_table_size = section_count as u64 * 64;
    let required_bytes = section_table_offset + section_table_size;
    let mut header_data = vec![0; required_bytes as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header_data)?;
    let elf = Elf::parse(&header_data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let section_table_end =
        elf.header.e_shoff + (elf.header.e_shentsize as u64 * elf.header.e_shnum as u64);
    let last_section_end = elf
        .section_headers
        .last()
        .map(|section| section.sh_offset + section.sh_size)
        .unwrap_or(0);
    Ok(section_table_end.max(last_section_end))
}

fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        rng = rng.wrapping_mul(48271).wrapping_rem(0x7FFFFFFF);
        let idx = (rng % CHARSET.len() as u64) as usize;
        result.push(CHARSET[idx] as char);
    }
    result
}

fn memfd_exec(exec_name: &str, exec_bytes: Vec<u8>, exec_args: Vec<String>) {
    let noexec_path = PathBuf::from("/proc/sys/vm/memfd_noexec");
    if noexec_path.exists() {
        match read_to_string(&noexec_path) {
            Ok(data) => {
                if !data.contains("0") {
                    eprint!("You need to enable memfd_noexec == 0: {:?} == {data}", &noexec_path);
                    exit(1)
                }
            }
            Err(err) => {
                eprintln!("Failed to read memfd_noexec: {err}: {:?}", &noexec_path);
                exit(1)
            }
        }
    }
    drop(noexec_path);
    MemFdExecutable::new(exec_name, &exec_bytes)
        .args(exec_args)
        .envs(env::vars())
        .exec(Stdio::inherit());
}

fn embed_exec(exec_name: &str, exec_bytes: Vec<u8>, exec_args: Vec<String>) {
    cfg_if! {
        if #[cfg(feature = "pie-ulexec")] {
            if !is_pie(&exec_bytes) {
                memfd_exec(exec_name, exec_bytes, exec_args)
            } else {
                match &memfd_create(
                    CString::new(exec_name).unwrap().as_c_str(),
                    MemFdCreateFlag::MFD_CLOEXEC
                ) {
                    Ok(memfd) => {
                        let memfd_raw = memfd.as_raw_fd();
                        let file_path = PathBuf::from(
                            format!("/proc/self/fd/{}", memfd_raw.to_string())
                        );
                        if let Err(err) = write(memfd, &exec_bytes) {
                            eprintln!("Failed to write the binary file to memfd: {err}: {:?}", file_path);
                            exit(1)
                        }
                        drop(exec_bytes);
                        let mut args_cstrs: Vec<CString> = exec_args.iter()
                            .map(|arg|
                                CString::new(arg.clone()).unwrap()
                        ).collect();
                        let file_cstr = CString::new(
                            file_path.to_str().unwrap()
                        ).unwrap();
                        args_cstrs.insert(0, file_cstr);
                        let envs: Vec<CString> = env::vars()
                            .map(|(key, value)|
                                CString::new(format!("{}={}", key, value)).unwrap()
                        ).collect();
                        spawn(move || {
                            sleep(Duration::from_millis(1));
                            close(memfd_raw).unwrap()
                        });
                        userland_execve::exec(
                            &file_path,
                            &args_cstrs,
                            &envs,
                        )
                    }
                    Err(err) => {
                        eprintln!("Failed to create memfd: {err}");
                        exit(1)
                    }
                }
            }
        } else {
            memfd_exec(exec_name, exec_bytes, exec_args)
        }
    }
}

fn is_mount_point(path: &PathBuf) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let device_id = metadata.dev();
    match path.parent() {
        Some(parent) => {
            let parent_metadata = fs::metadata(parent)?;
            Ok(device_id != parent_metadata.dev())
        }
        None => Ok(false)
    }
}

fn wait_mount(path: &PathBuf, timeout: Duration) -> bool {
    let start_time = Instant::now();
    while !path.exists() || !is_mount_point(path).unwrap_or(false) {
        if start_time.elapsed() >= timeout {
            eprintln!("Timeout reached while waiting for mount: {:?}", path);
            return false
        }
        sleep(Duration::from_millis(1))
    }
    true
}

fn remove_mnt(mount_dirs: Vec<&PathBuf> ) {
    for dir in mount_dirs {
        let _ = remove_dir(dir);
    }
}

fn mount_image(embed: Embed, image: Image, mount_dir: &PathBuf) {
    check_fuse();
    if let Err(err) = create_dir_all(&mount_dir) {
        eprintln!("Failed to create mount dir: {err}: {:?}", mount_dir);
        exit(1)
    }
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let num_threads = num_cpus::get();
            embed_exec("dwarfs", embed.dwarfs_universal, vec!["-f".into(),
                // "-o".into(), format!("offset=auto"),
                "-o".into(), format!("offset={}", image.offset),
                "-o".into(), format!("workers={num_threads}"),
                "-o".into(), format!("max_threads={num_threads}"),
                "-o".into(), "debuglevel=error".into(),
                image.path.to_str().unwrap().to_string(),
                mount_dir.to_str().unwrap().to_string()
            ])
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            embed_exec("squashfuse", embed.squashfuse, vec!["-f".into(),
                "-o".into(), format!("ro,offset={}", image.offset),
                image.path.to_str().unwrap().to_string(),
                mount_dir.to_str().unwrap().to_string()
            ])
        }
    }
}

fn extract_image(embed: Embed, image: Image) {
    cfg_if!{
        if #[cfg(feature = "appimage")] {
            let extract_dir = "AppDir";
            let applink_dir = "squashfs-root";
        } else {
            let extract_dir = "RunDir";
        }
    }
    if let Err(err) = create_dir(&extract_dir) {
        eprintln!("Failed to create extract dir: {err}: {}", &extract_dir);
        exit(1)
    }
    #[cfg(feature = "appimage")]
    {
        let _ = remove_file(&applink_dir);
        if let Err(err) = symlink(&extract_dir, &applink_dir) {
            eprintln!("Failed to create squashfs-root symlink to extract dir: {err}");
            exit(1)
        }
    }

    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            embed_exec("dwarfsextract", embed.dwarfs_universal, vec![
                "--input".into(), image.path.to_str().unwrap().to_string(),
                "--output".into(), extract_dir.into(),
                format!("--stdout-progress"),
                format!("--log-level=error"),
                // format!("--image-offset=auto"),
                format!("--image-offset={}", image.offset),
                format!("--num-workers={}", num_cpus::get())
            ])
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            embed_exec("unsquashfs", embed.unsquashfs, vec!["-f".into(),
                "-d".into(), extract_dir.into(),
                "-o".into(), image.offset.to_string(),
                image.path.to_str().unwrap().to_string(),
            ])
        }
    }
}

fn strip_str(str: &str) -> String {
    str.lines()
    .map(|line| line.trim_start())
    .collect::<Vec<_>>()
    .join("\n")
}

fn main() {
    let embed = Embed::default();
    let self_exe = &current_exe().unwrap();

    let runtime_size = get_runtime_size(self_exe).unwrap_or_else(|err|{
        eprintln!("Failed to get runtime size: {err}");
        exit(1)
    });

    let image = get_image(&self_exe, runtime_size).unwrap_or_else(|err|{
        eprintln!("Failed to get image: {err}");
        exit(1)
    });

    let mut exec_args: Vec<String> = env::args().collect();
    let arg0 = exec_args.remove(0);

    cfg_if!{
        if #[cfg(feature = "appimage")] {
            let arg_pfx = "appimage";
            let mount_dir = env::temp_dir().join(random_string(8));
            let mount_dirs = vec![&mount_dir];
        } else {
            let arg_pfx = "runtime";
            let uid = unsafe { nix::libc::getuid() };
            let ruid_dir = env::temp_dir().join(format!(".r{uid}"));
            let mnt_dir = ruid_dir.join("mnt");
            let mount_dir = mnt_dir.join(random_string(8));
            let mount_dirs = vec![&mount_dir, &mnt_dir, &ruid_dir];

        }
    }
    if !exec_args.is_empty() {
        if exec_args[0] == format!("--{arg_pfx}-extract") {
            extract_image(embed, image);
            return
        }
        if exec_args[0] == format!("--{arg_pfx}-mount") {
            println!("{}", mount_dir.display());
            mount_image(embed, image, &mount_dir);
            return
        }
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: child_pid }) => {
            if !wait_mount(&mount_dir, Duration::from_millis(1000)) {
                remove_mnt(mount_dirs);
                exit(1)
            }

            cfg_if!{
                if #[cfg(feature = "appimage")] {
                    let run = mount_dir.join("AppRun");
                    if !run.is_file() {
                        eprintln!("AppRun not found: {:?}", run);
                        remove_mnt(mount_dirs);
                        exit(1)
                    };
                    env::set_var("ARGV0", arg0);
                    env::set_var("APPDIR", &mount_dir);
                    env::set_var("APPIMAGE", self_exe);
                    env::set_var("APPOFFSET", format!("{runtime_size}"));
                } else {
                    let run = mount_dir.join("static").join("bash");
                    if !run.is_file() {
                        eprintln!("Static bash not found: {:?}", run);
                        remove_mnt(mount_dirs);
                        exit(1)
                    };
                    exec_args.insert(0, format!("{}/Run.sh", mount_dir.display()));
                    env::set_var("ARG0", arg0);
                    env::set_var("RUNDIR", &mount_dir);
                    env::set_var("RUNIMAGE", self_exe);
                    env::set_var("RUNOFFSET", format!("{runtime_size}"));
                }
            }
            env::set_var("OWD", getcwd().unwrap());

            let mut child = Command::new(run).args(&exec_args).spawn().unwrap();
            let pid = Pid::from_raw(child.id() as i32);
            let mut exit_code = 143;

            let mut signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT]).unwrap();
            let signals_handle = signals.handle();
            spawn(move || {
                for signal in signals.forever() {
                    match signal {
                        SIGINT | SIGTERM | SIGQUIT | SIGHUP => {
                            let _ = kill(pid, Signal::SIGTERM);
                            break
                        }
                        _ => {}
                    }
                }
            });

            if let Ok(status) = child.wait() {
                if let Some(code) = status.code() {
                    exit_code = code
                }
            }

            let _ = kill(child_pid, Signal::SIGTERM);
            let _ = waitpid(child_pid, None);
            signals_handle.close();

            remove_mnt(mount_dirs);

            exit(exit_code)
        }
        Ok(ForkResult::Child) => {
            mount_image(embed, image, &mount_dir)
        }
        Err(err) => {
            eprintln!("Fork error: {err}");
            exit(1)
        }
    }
}
