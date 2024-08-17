use anyhow::Result;

pub(crate) async fn cli_unpack(opts: crate::UnpackOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let descriptor = repo.pull(&proxy, &opts.image).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}
