use hyper::{Body, Client, Uri};

#[tokio::main]
async fn main() {
    let client = Client::new();
    let uri: Uri = "http://example.com".parse().unwrap();
    let resp = client.get(uri).await.unwrap();
    println!("Status: {}", resp.status());
}
