use std::time::Duration;

pub fn format_progress(phase: &str, done: usize, total: usize, elapsed: Duration) -> String {
    let eta = eta_duration(done, total, elapsed);
    format!("{phase} [{done}/{total}] ETA: {}", format_duration(eta))
}

fn eta_duration(done: usize, total: usize, elapsed: Duration) -> Duration {
    if done == 0 || done >= total {
        return Duration::ZERO;
    }
    let remaining = total - done;
    Duration::from_secs(((elapsed.as_secs_f64() / done as f64) * remaining as f64).round() as u64)
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m{:02}s", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_semantic_second_eta() {
        assert_eq!(
            format_progress("semantic", 2, 5, Duration::from_secs(10)),
            "semantic [2/5] ETA: 15s"
        );
    }

    #[test]
    fn formats_commits_minute_eta() {
        assert_eq!(
            format_progress("commits", 2, 5, Duration::from_secs(82)),
            "commits [2/5] ETA: 2m03s"
        );
    }

    #[test]
    fn formats_completed_eta_as_zero() {
        assert_eq!(
            format_progress("semantic", 5, 5, Duration::from_secs(10)),
            "semantic [5/5] ETA: 0s"
        );
    }

    #[test]
    fn formats_zero_done_eta_as_zero() {
        assert_eq!(
            format_progress("commits", 0, 4, Duration::from_secs(10)),
            "commits [0/4] ETA: 0s"
        );
    }
}
