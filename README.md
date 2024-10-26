# URUNTIME
Universal [RunImage](https://github.com/VHSgunzo/runimage) and [AppImage](https://appimage.org/) runtime with [SquashFS](https://docs.kernel.org/filesystems/squashfs.html) and [DwarFS](https://github.com/mhx/dwarfs) supports

## To get started:
* **Download the latest revision**
```
git clone https://github.com/VHSgunzo/uruntime.git && cd uruntime
```

* **Compile a binary**
```
rustup default nightly
rustup target add x86_64-unknown-linux-musl
rustup component add rust-src --toolchain nightly

cargo xtask
# Tasks:
#     x86_64                     build x86_64 RunImage and AppImage uruntime
#     runimage-x86_64            build x86_64 RunImage uruntime
#     runimage-squashfs-x86_64   build x86_64 RunImage uruntime (SquashFS only)
#     runimage-dwarfs-x86_64     build x86_64 RunImage uruntime (DwarFS only)
#     appimage-x86_64            build x86_64 AppImage uruntime
#     appimage-squashfs-x86_64   build x86_64 AppImage uruntime (SquashFS only)
#     appimage-dwarfs-x86_64     build x86_64 AppImage uruntime (DwarFS only)
#
#     aarch64                     build aarch64 RunImage and AppImage uruntime
#     runimage-aarch64            build aarch64 RunImage uruntime
#     runimage-squashfs-aarch64   build aarch64 RunImage uruntime (SquashFS only)
#     runimage-dwarfs-aarch64     build aarch64 RunImage uruntime (DwarFS only)
#     appimage-aarch64            build aarch64 AppImage uruntime
#     appimage-squashfs-aarch64   build aarch64 AppImage uruntime (SquashFS only)
#     appimage-dwarfs-aarch64     build aarch64 AppImage uruntime (DwarFS only)
# 
#     all                         build all of the above

# for RunImage x86_64
cargo xtask runimage-x86_64

# for AppImage x86_64
cargo xtask appimage-x86_64
```
See [Build step in ci.yml](https://github.com/VHSgunzo/uruntime/blob/main/.github/workflows/ci.yml#L34)

* Or take an already precompiled from the [releases](https://github.com/VHSgunzo/uruntime/releases)
