use std::path::Path;

use tokio::fs::{self, File};
use tokio::io::{self, AsyncWriteExt};

pub async fn safe_write(path: impl AsRef<Path>, buf: &[u8]) -> Result<(), io::Error> {
    let tmp = format!("{}.tmp", path.as_ref().display());

    let mut file = File::create(&tmp).await?;
    file.write_all(buf).await?;
    file.sync_all().await?;
    drop(file);

    fs::rename(&tmp, &path).await?;

    Ok(())
}
