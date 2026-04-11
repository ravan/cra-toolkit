// Minimal application that uses chrono to format the current time.
// CVE-2020-26235 in time@0.2.23 is transitively reachable because chrono
// internally calls into time's public API (specifically time::OffsetDateTime
// methods) to construct DateTime values.

use chrono::Utc;

fn format_now() -> String {
    let now = Utc::now();
    now.to_rfc3339()
}

fn main() {
    println!("{}", format_now());
}
