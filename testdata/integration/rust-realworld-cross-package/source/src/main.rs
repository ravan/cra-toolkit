// Minimal application that generates a UUID v4.
// uuid::Uuid::new_v4() calls getrandom::getrandom() internally via
// crate::rng::bytes() — getrandom@0.2.11 is transitively reachable.

use uuid::Uuid;

fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

fn main() {
    println!("{}", generate_id());
}
