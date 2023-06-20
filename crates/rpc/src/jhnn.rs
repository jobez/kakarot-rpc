use reth_downloaders::test_utils::FileClient;
use std::{env, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Please provide a file path");
        return Ok(());
    }
    let path = &args[1];
    let path_buf = PathBuf::from(path);

    let file_client = Arc::new(FileClient::new(&path_buf).await?);
    dbg!(file_client);
    Ok(())
}
