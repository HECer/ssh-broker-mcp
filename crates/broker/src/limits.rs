#[derive(Debug, Clone)]
pub struct Limits {
    pub max_exec_output_bytes: usize,
    pub max_shell_output_bytes: usize,
    pub max_shell_seconds: u64,
    pub max_scp_bytes: u64,
}
