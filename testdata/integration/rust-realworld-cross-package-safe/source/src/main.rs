// Minimal application that uses chrono's Duration type for arithmetic only.
// chrono::Duration is implemented inside chrono and does NOT touch time's
// vulnerable surface (time::OffsetDateTime). CVE-2020-26235 should be
// not_affected for this application.

use chrono::Duration;

fn seconds_in_an_hour() -> i64 {
    Duration::hours(1).num_seconds()
}

fn main() {
    println!("{}", seconds_in_an_hour());
}
