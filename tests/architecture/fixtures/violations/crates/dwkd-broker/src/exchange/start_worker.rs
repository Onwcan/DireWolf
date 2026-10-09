// VIOLATES TX049: a second place that names -- and so could start -- the
// exchange worker, outside the HTTPS client that judged the hop and dialled
// its pinned address first.
pub const WORKER_MODE: &str = "http-worker";
