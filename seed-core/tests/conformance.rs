use seed_core::conformance::{memory::MemoryHarness, report, run_all, Harness};

#[test]
fn reference_door_passes_every_conformance_case() {
    let results = run_all(&mut || Box::new(MemoryHarness::default()) as Box<dyn Harness>);
    println!("{}", report(&results));
    assert_eq!(results.len(), 17);
    assert!(results.iter().all(|r| r.passed), "{}", report(&results));
}
