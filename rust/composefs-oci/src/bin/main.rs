use anyhow::Result;

/// The code called after we've done process global init and created
/// an async runtime.
async fn async_main() -> Result<()> {
    // As you can see, the role of this file is mostly to just be a shim
    // to call into the code that lives in the internal shared library.
    composefs_oci::run_from_iter(std::env::args()).await
}

/// Perform process global initialization, then create an async runtime
/// and do the rest of the work there.
fn run() -> Result<()> {
    // We only use the "current thread" runtime because we don't perform
    // a lot of CPU heavy work in async tasks. Where we do work on the CPU,
    // or we do want explicit concurrency, we typically use
    // tokio::task::spawn_blocking to create a new OS thread explicitly.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");
    // And invoke the async_main
    runtime.block_on(async move { async_main().await })
}

fn main() {
    // In order to print the error in a custom format (with :#) our
    // main simply invokes a run() where all the work is done.
    // This code just captures any errors.
    if let Err(e) = run() {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
