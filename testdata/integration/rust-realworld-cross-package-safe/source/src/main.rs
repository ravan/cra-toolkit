// Minimal application that parses a UUID from a string literal.
// uuid::Uuid::parse_str() is a pure parsing function and does NOT call
// getrandom::getrandom() — it needs no entropy. getrandom@0.2.11 is
// transitively present in the dependency graph but not reachable from app code.

use uuid::Uuid;

fn is_valid_id(s: &str) -> bool {
    Uuid::parse_str(s).is_ok()
}

fn main() {
    println!("{}", is_valid_id("550e8400-e29b-41d4-a716-446655440000"));
}
