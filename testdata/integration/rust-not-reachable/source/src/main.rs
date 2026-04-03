use hyper::{Body, Client, Uri};

#[tokio::main]
async fn main() {
    // Only uses HTTP/1.1 client - does NOT use the vulnerable HTTP/2 server code
    let client = Client::new();
    let uri: Uri = "http://httpbin.org/get".parse().unwrap();

    match client.get(uri).await {
        Ok(resp) => println!("Response status: {}", resp.status()),
        Err(err) => eprintln!("Error: {}", err),
    }
}
