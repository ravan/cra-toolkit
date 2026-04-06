use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn handle(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("OK")))
}

pub async fn run() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000))).await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let http = Http::new();
    let http = http.http2_only(true);
    http.serve_connection(stream, service_fn(handle)).await.unwrap();
}
