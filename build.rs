use std::{
    env,
    path::Path,
    process::{exit, Command},
    os::unix::fs::{symlink, PermissionsExt},
    fs::{create_dir, remove_file, set_permissions, Permissions}
};

use cfg_if::cfg_if;
use indexmap::IndexMap;


fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let project = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_path = Path::new(&project);

    let assets_path = project_path.join(format!("assets-{arch}"));
    let assets_path_link = project_path.join("assets");

    let assets = IndexMap::from([
        #[cfg(feature = "squashfs")]
        ("squashfuse", format!("https://github.com/VHSgunzo/squashfuse-static/releases/download/v0.6.0.r0.gac22ad1/squashfuse-musl-mimalloc-{arch}")),
        #[cfg(feature = "squashfs")]
        ("unsquashfs", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v4.6.1/unsquashfs-{arch}")),
        #[cfg(feature = "mksquashfs")]
        ("mksquashfs", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v4.6.1/mksquashfs-{arch}")),
        #[cfg(feature = "dwarfs")]
        ("dwarfs-universal", format!("https://github.com/VHSgunzo/dwarfs/releases/download/v0.11.3/dwarfs-universal-{arch}")),
    ]);

    if !assets_path.exists() {
        create_dir(&assets_path).unwrap()
    }

    let _ = remove_file(&assets_path_link);
    symlink(&assets_path, &assets_path_link).unwrap();

    for asset in assets.keys() {
        cfg_if! {
            if #[cfg(feature = "upx")] {
                let asset_path = assets_path.join(format!("{asset}-upx"));
                let asset_url = &format!("{}-upx", assets.get(asset).unwrap());
            } else {
                let asset_path = assets_path.join(asset);
                let asset_url = assets.get(asset).unwrap();
            }
        }

        if !asset_path.exists() {
            let output = Command::new("curl").args([
                "--insecure",
                "-L", asset_url,
                "-o", asset_path.to_str().unwrap()
            ]).output().unwrap_or_else(|err| panic!("Failed to execute curl: {err}: {asset}"));

            if !output.status.success() {
                eprintln!("Failed to get asset: {}", String::from_utf8_lossy(&output.stderr));
                exit(1)
            }

            set_permissions(&asset_path, Permissions::from_mode(0o755))
                .unwrap_or_else(|err| panic!("Unable to set permissions: {err}: {asset}"));
        }

        #[cfg(not(feature = "upx"))]
        {
            let asset_zstd_path = assets_path.join(format!("{asset}-zst"));
            if !asset_zstd_path.exists() {
                let asset_data = std::fs::read(asset_path).unwrap();
                let asset_zstd_data = zstd::stream::encode_all(&asset_data[..], 22).unwrap();
                std::fs::write(asset_zstd_path, asset_zstd_data).unwrap();
            }
        }
    }
}
