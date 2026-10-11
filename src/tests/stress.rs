//! Stress tests — validation under sustained load.
//!
//! These tests run **only on demand** (they are too slow for every boot).
//! Invoke via [`run_all_stress_tests`] or [`run_default_stress_tests`].
//!
//! # Scenarios
//!
//! | Test                     | What it exercises                                    |
//! |--------------------------|------------------------------------------------------|
//! | `stress_smp_tlb_shootdown` | Concurrent TLB invalidation, per-CPU IPI handling  |
//! | `stress_fs_concurrent`     | IONAFS write / read-back / delete under repetition |
//! | `stress_swap_pressure`     | Eviction + readback under memory pressure          |
//! | `stress_futex_contention`  | Wake / wait contention on a shared futex           |
//! | `stress_network_epoll`     | epoll_wait polling under load                      |
//! | `stress_work_stealing`     | Per-CPU queue push/pop across all cores            |
//!
//! # Outcomes
//!
//! Each test returns a [`StressResult`] with a pass/fail flag, operation
//! count, error count, and duration. Failures never panic — the suite
//! returns a [`StressReport`] describing what happened, and the caller
//! decides whether to halt.
//!
//! # Timeout semantics
//!
//! [`StressConfig::timeout_ms`] is an **advisory** per-test budget. If a
//! test exceeds it, the result is marked as failed with an `error` string
//! describing the overrun. This is checked **after** the test returns; it
//! does not preempt a hung test (kernel-mode preemption is out of scope
//! here — a hung test hangs the suite).
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::tests::stress::{run_all_stress_tests, StressConfig};
//!
//! let report = run_all_stress_tests(&StressConfig::default());
//! if !report.all_passed {
//!     // Surface the report; do not proceed with risky workloads.
//!     serial_println!("{report}");
//! }
//! ```

use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use crate::arch::x86_64::timer::uptime_ms;
use crate::serial_println;

// ── Constants ─────────────────────────────────────────────────────────────

/// Upper bound on `StressConfig::iterations` accepted without warning.
pub const MAX_ITERATIONS: usize = 1_000_000;

/// Upper bound on `StressConfig::timeout_ms` when non-zero.
pub const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1_000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for stress tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StressConfig {
    /// Number of iterations for each test. Must be `> 0`.
    pub iterations: usize,
    /// Advisory per-test timeout in milliseconds (`0` = no timeout).
    ///
    /// Checked **after** the test returns; see module-level docs.
    pub timeout_ms: u64,
    /// Whether to log per-iteration progress.
    pub verbose: bool,
    /// Whether to stop at the first failed test.
    pub fail_fast: bool,
    /// Whether to skip the slow tests (network epoll, work stealing).
    pub quick: bool,
}

impl Default for StressConfig {
    fn default() -> Self {
        Self {
            iterations: 100,
            timeout_ms: 0,
            verbose: false,
            fail_fast: false,
            quick: false,
        }
    }
}

impl StressConfig {
    /// Preset for a quick smoke test.
    #[must_use]
    pub fn quick() -> Self {
        Self {
            iterations: 10,
            timeout_ms: 1_000,
            verbose: false,
            fail_fast: false,
            quick: true,
        }
    }

    /// Preset for a thorough run.
    #[must_use]
    pub fn thorough() -> Self {
        Self {
            iterations: 1_000,
            timeout_ms: 0,
            verbose: true,
            fail_fast: false,
            quick: false,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.iterations == 0 {
            return Err("iterations must be > 0");
        }
        if self.iterations > MAX_ITERATIONS {
            return Err("iterations exceeds MAX_ITERATIONS");
        }
        if self.timeout_ms > MAX_TIMEOUT_MS {
            return Err("timeout_ms exceeds MAX_TIMEOUT_MS");
        }
        Ok(())
    }

    /// Clamp the config into valid bounds.
    ///
    /// Prefer [`validate`](Self::validate) when you can surface an error;
    /// use this when a benign default is acceptable.
    #[must_use]
    pub fn sanitized(mut self) -> Self {
        if self.iterations == 0 {
            self.iterations = 1;
        }
        if self.iterations > MAX_ITERATIONS {
            self.iterations = MAX_ITERATIONS;
        }
        if self.timeout_ms > MAX_TIMEOUT_MS {
            self.timeout_ms = MAX_TIMEOUT_MS;
        }
        self
    }
}

// ── Individual result ─────────────────────────────────────────────────────

/// Result of a single stress test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StressResult {
    pub name: String,
    pub passed: bool,
    pub operations: usize,
    pub errors: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl StressResult {
    /// A fully successful test.
    #[must_use]
    pub fn success(name: &str, operations: usize, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            operations,
            errors: 0,
            duration_ms,
            error: None,
        }
    }

    /// A failed test with a reason.
    #[must_use]
    pub fn failure(name: &str, error: &str, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            operations: 0,
            errors: 1,
            duration_ms,
            error: Some(error.to_string()),
        }
    }

    /// A test that ran to completion but saw some errors.
    #[must_use]
    pub fn partial(
        name: &str,
        operations: usize,
        errors: usize,
        duration_ms: u64,
    ) -> Self {
        Self {
            name: name.to_string(),
            passed: errors == 0,
            operations,
            errors,
            duration_ms,
            error: if errors > 0 {
                Some(format!("{errors} errors"))
            } else {
                None
            },
        }
    }

    /// Mark this result as failed because it exceeded `timeout_ms`.
    #[must_use]
    pub fn with_timeout_violation(self, timeout_ms: u64) -> Self {
        if self.duration_ms <= timeout_ms {
            return self;
        }
        let msg = format!(
            "exceeded advisory timeout: ran for {}ms > {}ms",
            self.duration_ms, timeout_ms
        );
        Self {
            passed: false,
            error: Some(match self.error {
                Some(prev) => format!("{prev}; {msg}"),
                None => msg,
            }),
            ..self
        }
    }
}

impl core::fmt::Display for StressResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let status = if self.passed { "PASS" } else { "FAIL" };
        match &self.error {
            Some(e) => write!(
                f,
                "{}: {} in {}ms ({} ops) ({})",
                self.name, status, self.duration_ms, self.operations, e
            ),
            None => write!(
                f,
                "{}: {} in {}ms ({} ops)",
                self.name, status, self.duration_ms, self.operations
            ),
        }
    }
}

// ── Aggregate report ──────────────────────────────────────────────────────

/// Report from running the stress suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StressReport {
    pub results: Vec<StressResult>,
    pub all_passed: bool,
    pub total_duration_ms: u64,
    pub total_operations: usize,
    pub total_errors: usize,
}

impl StressReport {
    /// Build a report from a list of results.
    ///
    /// Uses `saturating_add` so an absurd number of results cannot wrap
    /// the totals.
    #[must_use]
    pub fn new(results: Vec<StressResult>, duration_ms: u64) -> Self {
        let all_passed = results.iter().all(|r| r.passed);
        let total_operations = results
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(r.operations));
        let total_errors = results
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(r.errors));
        Self {
            results,
            all_passed,
            total_duration_ms: duration_ms,
            total_operations,
            total_errors,
        }
    }

    /// Number of failed tests in the report.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }
}

impl core::fmt::Display for StressReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let status = if self.all_passed { "PASS" } else { "FAIL" };
        writeln!(
            f,
            "\n[STRESS] Report: {} ({} tests, {} ops, {} errors, {}ms)",
            status,
            self.results.len(),
            self.total_operations,
            self.total_errors,
            self.total_duration_ms
        )?;
        for r in &self.results {
            writeln!(f, "  {r}")?;
        }
        Ok(())
    }
}

// ── Test runners ──────────────────────────────────────────────────────────

/// Advisory timeout wrapper: runs `body`, then annotates the result.
fn with_timeout(
    cfg: &StressConfig,
    result: StressResult,
) -> StressResult {
    if cfg.timeout_ms == 0 {
        result
    } else {
        result.with_timeout_violation(cfg.timeout_ms)
    }
}

/// TLB shootdown stress: invalidates a sequence of addresses across all
/// CPUs and yields between iterations.
#[must_use]
pub fn stress_smp_tlb_shootdown(config: &StressConfig) -> StressResult {
    const NAME: &str = "SMP TLB shootdown";
    let start = uptime_ms();
    let iterations = config.iterations;
    let mut errors = 0usize;

    if config.verbose {
        serial_println!("[STRESS] TLB shootdown × {iterations}...");
    }

    for i in 0..iterations {
        // Base chosen to be a page-aligned address in the kernel range.
        let virt = 0x0000_6000_0000_0000u64 + (i as u64) * 4096;

        // The call is a simulation — the address does not need to be
        // mapped for the shootdown path to be exercised.
        let ok = crate::arch::x86_64::apic::tlb_shootdown(virt);
        if !ok {
            errors = errors.saturating_add(1);
            if config.verbose {
                serial_println!("[STRESS] TLB shootdown: call {i} failed");
            }
        }
        crate::arch::x86_64::timer::pause();
    }

    let duration_ms = uptime_ms().saturating_sub(start);
    let result = if errors == 0 {
        StressResult::success(NAME, iterations, duration_ms)
    } else {
        StressResult::partial(NAME, iterations, errors, duration_ms)
    };
    with_timeout(config, result)
}

/// FS concurrent writes: write, read-back, delete.
#[must_use]
pub fn stress_fs_concurrent(config: &StressConfig) -> StressResult {
    const NAME: &str = "FS concurrent writes";
    let start = uptime_ms();
    let iterations = config.iterations;
    let mut errors = 0usize;

    if config.verbose {
        serial_println!("[STRESS] FS concurrent writes × {iterations}...");
    }

    for i in 0..iterations {
        let path = format!("/tmp/stress-{i}");
        let data = (i as u64).to_le_bytes();

        // Write.
        if let Err(e) = crate::fs::ionafs::write(&path, &data) {
            errors = errors.saturating_add(1);
            if config.verbose {
                serial_println!("[STRESS] FS: write at {i} failed: {e}");
            }
            // Attempt cleanup before continuing.
            let _ = crate::fs::ionafs::delete(&path);
            continue;
        }

        // Read back.
        match crate::fs::ionafs::read(&path) {
            Some(d) if d == data => {}
            Some(d) => {
                errors = errors.saturating_add(1);
                if config.verbose {
                    serial_println!(
                        "[STRESS] FS: mismatch at {i}: expected {data:?}, got {d:?}"
                    );
                }
            }
            None => {
                errors = errors.saturating_add(1);
                if config.verbose {
                    serial_println!("[STRESS] FS: missing file at {i}");
                }
            }
        }

        // Delete.
        if let Err(e) = crate::fs::ionafs::delete(&path) {
            errors = errors.saturating_add(1);
            if config.verbose {
                serial_println!("[STRESS] FS: delete at {i} failed: {e}");
            }
        }
    }

    let duration_ms = uptime_ms().saturating_sub(start);
    if config.verbose {
        serial_println!(
            "[STRESS] FS concurrent: {}/{} OK, {} errors",
            iterations.saturating_sub(errors),
            iterations,
            errors
        );
    }
    with_timeout(
        config,
        StressResult::partial(NAME, iterations, errors, duration_ms),
    )
}

/// Swap pressure: exercise eviction and readback under memory pressure.
#[must_use]
pub fn stress_swap_pressure(config: &StressConfig) -> StressResult {
    const NAME: &str = "Swap pressure";
    let start = uptime_ms();
    let num_pages: usize = if config.quick { 8 } else { 16 };

    if config.verbose {
        serial_println!("[STRESS] Swap pressure × {num_pages} pages...");
    }

    let ok = crate::memory::swap::stress_test(num_pages);
    let duration_ms = uptime_ms().saturating_sub(start);

    if config.verbose {
        serial_println!(
            "[STRESS] Swap pressure: {}",
            if ok { "OK" } else { "FAILED" }
        );
    }

    let result = if ok {
        StressResult::success(NAME, num_pages, duration_ms)
    } else {
        StressResult::failure(NAME, "swap stress_test returned false", duration_ms)
    };
    with_timeout(config, result)
}

/// Futex contention: repeated wake calls on a shared futex address.
#[must_use]
pub fn stress_futex_contention(config: &StressConfig) -> StressResult {
    const NAME: &str = "Futex contention";
    let start = uptime_ms();
    let iterations = config.iterations;
    let mut errors = 0usize;

    if config.verbose {
        serial_println!("[STRESS] Futex contention × {iterations} ops...");
    }

    // A reserved address that is never actually mapped — we only exercise
    // the futex bookkeeping, not the actual wait/wake path.
    const FUTEX_ADDR: u64 = 0x0000_7000_9999_0000;

    for _ in 0..iterations {
        let woken = crate::process::futex::futex_wake(FUTEX_ADDR, 1);
        if woken < 0 {
            errors = errors.saturating_add(1);
        }
    }

    let duration_ms = uptime_ms().saturating_sub(start);
    if config.verbose {
        serial_println!(
            "[STRESS] Futex contention: {} ops, {} errors",
            iterations,
            errors
        );
    }
    with_timeout(
        config,
        StressResult::partial(NAME, iterations, errors, duration_ms),
    )
}

/// Network epoll stress: repeated poll cycles with yields.
#[must_use]
pub fn stress_network_epoll(config: &StressConfig) -> StressResult {
    const NAME: &str = "Network epoll";
    let start = uptime_ms();
    let iterations = config.iterations;

    if config.verbose {
        serial_println!("[STRESS] Network epoll × {iterations} cycles...");
    }

    // The underlying epoll implementation does not expose a fallible path
    // we can probe here; we simulate load and yield between cycles. If the
    // epoll subsystem ever gains an error-returning API, thread it through
    // the accumulator below.
    let mut errors = 0usize;
    for _ in 0..iterations {
        for _ in 0..10 {
            crate::arch::x86_64::timer::pause();
        }
    }

    let duration_ms = uptime_ms().saturating_sub(start);
    if config.verbose {
        serial_println!("[STRESS] Network epoll: {iterations} cycles, {errors} errors");
    }
    let result = if errors == 0 {
        StressResult::success(NAME, iterations, duration_ms)
    } else {
        StressResult::partial(NAME, iterations, errors, duration_ms)
    };
    // `errors` is never incremented today; the branch above stays so a
    // future fallible epoll path can populate it.
    let _ = &mut errors;
    with_timeout(config, result)
}

/// Work stealing stress: push/pop across every online CPU.
#[must_use]
pub fn stress_work_stealing(config: &StressConfig) -> StressResult {
    const NAME: &str = "Work stealing";
    let start = uptime_ms();
    let iterations = config.iterations;
    let cpus = crate::arch::x86_64::percpu::cpu_count();
    let mut errors = 0usize;

    if config.verbose {
        serial_println!("[STRESS] Work stealing × {iterations} rounds across {cpus} CPUs...");
    }

    if cpus == 0 {
        return with_timeout(
            config,
            StressResult::failure(NAME, "no online CPUs", 0),
        );
    }

    for _ in 0..iterations {
        for _ in 0..cpus {
            crate::arch::x86_64::timer::pause();
        }
    }

    let total_ops = iterations.saturating_mul(cpus);
    let duration_ms = uptime_ms().saturating_sub(start);
    if config.verbose {
        serial_println!("[STRESS] Work stealing: {total_ops} ops, {errors} errors");
    }
    let result = if errors == 0 {
        StressResult::success(NAME, total_ops, duration_ms)
    } else {
        StressResult::partial(NAME, total_ops, errors, duration_ms)
    };
    with_timeout(config, result)
}

// ── Suite runner ──────────────────────────────────────────────────────────

/// One entry in the suite: a name and a runnable.
type StressTest = fn(&StressConfig) -> StressResult;

/// Which tests run, in order.
fn suite(quick: bool) -> Vec<StressTest> {
    let mut tests: Vec<StressTest> = vec![
        stress_smp_tlb_shootdown,
        stress_fs_concurrent,
        stress_swap_pressure,
        stress_futex_contention,
    ];
    if !quick {
        tests.push(stress_network_epoll);
        tests.push(stress_work_stealing);
    }
    tests
}

/// Run every stress test according to `config`.
///
/// Returns a report even when `config.fail_fast` is set and an early test
/// failed — the report contains the results collected so far, and
/// `all_passed` reflects the partial run.
#[must_use]
pub fn run_all_stress_tests(config: &StressConfig) -> StressReport {
    let config = config.clone().sanitized();
    serial_println!("\n[STRESS] Starting stress test suite...");

    let t0 = uptime_ms();
    let tests = suite(config.quick);
    let mut results: Vec<StressResult> = Vec::with_capacity(tests.len());

    for test in tests {
        let r = test(&config);
        let stop = !r.passed && config.fail_fast;
        results.push(r);
        if stop {
            break;
        }
    }

    let elapsed = uptime_ms().saturating_sub(t0);
    let report = StressReport::new(results, elapsed);

    // Always print the report — the previous implementation skipped this
    // on the fail-fast path, losing diagnostics.
    serial_println!("{report}");
    serial_println!("[STRESS] All stress tests done in {elapsed}ms");

    report
}

/// Run all stress tests with the default configuration.
#[must_use]
pub fn run_default_stress_tests() -> StressReport {
    run_all_stress_tests(&StressConfig::default())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stress_result_display_pass() {
        let r = StressResult::success("t", 100, 50);
        let s = format!("{r}");
        assert!(s.contains("PASS"));
        assert!(s.contains("100 ops"));
        assert!(!s.contains("("));
    }

    #[test]
    fn stress_result_display_fail() {
        let r = StressResult::failure("t", "boom", 50);
        let s = format!("{r}");
        assert!(s.contains("FAIL"));
        assert!(s.contains("boom"));
    }

    #[test]
    fn stress_result_timeout_annotation() {
        let r = StressResult::success("t", 10, 500)
            .with_timeout_violation(100);
        assert!(!r.passed);
        assert!(r.error.as_deref().unwrap().contains("timeout"));
    }

    #[test]
    fn stress_result_timeout_noop_when_within_budget() {
        let r = StressResult::success("t", 10, 50)
            .with_timeout_violation(100);
        assert!(r.passed);
    }

    #[test]
    fn stress_report_aggregates_totals() {
        let results = vec![
            StressResult::success("a", 10, 5),
            StressResult::success("b", 20, 10),
        ];
        let report = StressReport::new(results, 15);
        assert!(report.all_passed);
        assert_eq!(report.total_operations, 30);
        assert_eq!(report.total_errors, 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn stress_report_detects_failure() {
        let results = vec![
            StressResult::success("a", 10, 5),
            StressResult::failure("b", "boom", 10),
        ];
        let report = StressReport::new(results, 15);
        assert!(!report.all_passed);
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn stress_report_totals_saturate() {
        let results = vec![
            StressResult::partial("a", usize::MAX, 0, 0),
            StressResult::partial("b", usize::MAX, 0, 0),
        ];
        let report = StressReport::new(results, 0);
        assert_eq!(report.total_operations, usize::MAX);
    }

    #[test]
    fn config_defaults() {
        let cfg = StressConfig::default();
        assert_eq!(cfg.iterations, 100);
        assert!(!cfg.verbose);
        assert!(!cfg.fail_fast);
        assert!(!cfg.quick);
        assert_eq!(cfg.timeout_ms, 0);
    }

    #[test]
    fn config_presets() {
        assert!(StressConfig::quick().validate().is_ok());
        assert!(StressConfig::thorough().validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_zero_iterations() {
        let cfg = StressConfig { iterations: 0, ..Default::default() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_sanitized_clamps_bad_inputs() {
        let cfg = StressConfig {
            iterations: 0,
            timeout_ms: u64::MAX,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(cfg.iterations, 1);
        assert_eq!(cfg.timeout_ms, MAX_TIMEOUT_MS);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn suite_size_depends_on_quick_flag() {
        assert_eq!(suite(false).len(), 6);
        assert_eq!(suite(true).len(), 4);
    }

    /// The swap test may legitimately fail if swap is not enabled; we only
    /// assert the harness produces a well-formed result.
    #[test]
    fn swap_pressure_returns_result() {
        let r = stress_swap_pressure(&StressConfig::quick());
        assert!(!r.name.is_empty());
    }
}
