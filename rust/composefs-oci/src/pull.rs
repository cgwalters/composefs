use anyhow::Result;

use crate::PullOpts;

pub(crate) async fn cli_pull(opts: PullOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let descriptor = repo.pull_artifact(&proxy, &opts.image).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}
