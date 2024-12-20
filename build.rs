use std::{
    env,
    path::Path,
    process::{exit, Command},
    os::unix::fs::{symlink, PermissionsExt},
    fs::{create_dir, remove_file, set_permissions, Permissions}
};

use indexmap::IndexMap;


fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let project = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_path = Path::new(&project);

    let assets_path = project_path.join(format!("assets-{arch}"));
    let assets_path_link = project_path.join("assets");

    let assets = IndexMap::from([
        #[cfg(feature = "squashfs")]
        ("squashfuse-upx", format!("https://github.com/VHSgunzo/squashfuse-static/releases/download/v0.5.2.r6.g4289904/squashfuse-{arch}-upx")),
        #[cfg(feature = "squashfs")]
        ("unsquashfs-upx", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v4.6.1/unsquashfs-{arch}-upx")),
        #[cfg(feature = "mksquashfs")]
        ("mksquashfs-upx", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v4.6.1/mksquashfs-{arch}-upx")),
        #[cfg(feature = "dwarfs")]
        ("dwarfs-universal-upx", format!("https://github.com/VHSgunzo/dwarfs-universal-artifacts/releases/download/v0.10.2-126-gcaa0d97555/dwarfs-universal-Linux-{arch}-clang-O2")),
    ]);

    if !assets_path.exists() {
        create_dir(&assets_path).unwrap()
    }

    let _ = remove_file(&assets_path_link);
    symlink(&assets_path, &assets_path_link).unwrap();

    for asset in assets.keys() {
        let asset_path = assets_path.join(asset);
        let asset_upx_path = assets_path.join(format!("{asset}-upx"));

        if !asset_path.exists() {
            let output = Command::new("curl").args([
                "--insecure",
                "-L", assets.get(asset).unwrap(),
                "-o", asset_path.to_str().unwrap()
            ]).output().unwrap_or_else(|err| panic!("Failed to execute curl: {err}: {asset}"));

            if !output.status.success() {
                eprintln!("Failed to get asset: {}", String::from_utf8_lossy(&output.stderr));
                exit(1)
            }

            set_permissions(&asset_path, Permissions::from_mode(0o755))
                .unwrap_or_else(|err| panic!("Unable to set permissions: {err}: {asset}"));
        }

        if !asset.ends_with("upx") && !asset_upx_path.exists() {
            let output = Command::new("upx").args([
                "--force-overwrite", "-9", "--best",
                asset_path.to_str().unwrap(), "-o",
                asset_upx_path.to_str().unwrap()
            ]).output().unwrap_or_else(|err| panic!("Failed to execute upx: {err}: {asset}"));

            if !output.status.success() {
                eprintln!("Failed to upx asset: {}", String::from_utf8_lossy(&output.stderr));
                exit(1)
            }
        }
    }
}
