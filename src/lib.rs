/*!
# cuda-sandbox

Execution isolation for agents.

Agents experiment, and experiments can fail spectacularly. The sandbox
prevents one agent's mistake from becoming the fleet's catastrophe.

- Resource limits (memory, CPU, network)
- Execution isolation (fault containment)
- Operation whitelists/blacklists
- Safe experimentation mode
- Rollback on fault
- Sandbox telemetry
*/

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Sandbox resource limits
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: usize,
    pub max_cpu_percent: f64,
    pub max_operations: u64,
    pub max_network_calls: u64,
    pub max_duration_ms: u64,
    pub max_output_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self { ResourceLimits { max_memory_bytes: 64 * 1024 * 1024, max_cpu_percent: 80.0, max_operations: 100_000, max_network_calls: 50, max_duration_ms: 30_000, max_output_size: 1024 * 1024 } }
}

/// Resource usage tracking
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_bytes: usize,
    pub cpu_percent: f64,
    pub operations: u64,
    pub network_calls: u64,
    pub duration_ms: u64,
    pub output_size: usize,
    pub start_time: u64,
}

impl ResourceUsage {
    pub fn exceeded(&self, limits: &ResourceLimits) -> Option<String> {
        if self.memory_bytes > limits.max_memory_bytes { return Some("memory exceeded".into()); }
        if self.cpu_percent > limits.max_cpu_percent { return Some("cpu exceeded".into()); }
        if self.operations > limits.max_operations { return Some("operations exceeded".into()); }
        if self.network_calls > limits.max_network_calls { return Some("network exceeded".into()); }
        if self.duration_ms > limits.max_duration_ms { return Some("duration exceeded".into()); }
        if self.output_size > limits.max_output_size { return Some("output exceeded".into()); }
        None
    }

    pub fn utilization(&self, limits: &ResourceLimits) -> f64 {
        let metrics = vec![
            self.memory_bytes as f64 / limits.max_memory_bytes as f64,
            self.cpu_percent / limits.max_cpu_percent,
            self.operations as f64 / limits.max_operations as f64,
            self.network_calls as f64 / limits.max_network_calls as f64,
            self.duration_ms as f64 / limits.max_duration_ms as f64,
            self.output_size as f64 / limits.max_output_size as f64,
        ];
        metrics.into_iter().fold(0.0_f64, f64::max)
    }
}

/// Operation policy
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationPolicy { Allow, Deny, Log, RateLimit }

/// Sandbox configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub limits: ResourceLimits,
    pub operation_policy: HashMap<String, OperationPolicy>, // op name → policy
    pub read_only: bool,
    pub auto_rollback_on_fault: bool,
    pub max_retries: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        let mut policy = HashMap::new();
        policy.insert("file_write".into(), OperationPolicy::Allow);
        policy.insert("network_get".into(), OperationPolicy::Allow);
        policy.insert("network_post".into(), OperationPolicy::RateLimit);
        policy.insert("system_exec".into(), OperationPolicy::Deny);
        policy.insert("memory_alloc".into(), OperationPolicy::Allow);
        SandboxConfig { limits: ResourceLimits::default(), operation_policy: policy, read_only: false, auto_rollback_on_fault: true, max_retries: 3 }
    }
}

/// Operation record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation: String,
    pub allowed: bool,
    pub timestamp: u64,
    pub blocked_reason: Option<String>,
}

/// A fault that occurred in the sandbox
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fault {
    pub operation: String,
    pub error: String,
    pub timestamp: u64,
    pub severity: FaultSeverity,
    pub recovered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultSeverity { Warning, Error, Critical }

/// Execution mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode { Normal, Strict, Experiment, DryRun }

/// The sandbox
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: String,
    pub agent_id: String,
    pub config: SandboxConfig,
    pub usage: ResourceUsage,
    pub operations: Vec<OperationRecord>,
    pub faults: Vec<Fault>,
    pub mode: ExecutionMode,
    pub active: bool,
    pub created: u64,
    pub snapshots: Vec<Vec<u8>>,  // state snapshots for rollback
}

impl Sandbox {
    pub fn new(id: &str, agent_id: &str) -> Self {
        Sandbox { id: id.to_string(), agent_id: agent_id.to_string(), config: SandboxConfig::default(), usage: ResourceUsage::default(), operations: vec![], faults: vec![], mode: ExecutionMode::Normal, active: true, created: now(), snapshots: vec![] }
    }

    /// Check if an operation is allowed
    pub fn check_operation(&mut self, operation: &str) -> OperationCheck {
        // Check read-only mode
        if self.config.read_only && is_write_operation(operation) {
            self.record_operation(operation, false, Some("read-only sandbox"));
            return OperationCheck { allowed: false, reason: "read-only sandbox".into() };
        }

        // Check resource limits
        if let Some(exceeded) = self.usage.exceeded(&self.config.limits) {
            self.record_operation(operation, false, Some(&exceeded));
            return OperationCheck { allowed: false, reason: exceeded };
        }

        // Check operation policy
        let policy = self.config.operation_policy.get(operation).copied().unwrap_or(OperationPolicy::Allow);
        match policy {
            OperationPolicy::Allow => {
                self.record_operation(operation, true, None);
                OperationCheck { allowed: true, reason: String::new() }
            }
            OperationPolicy::Deny => {
                self.record_operation(operation, false, Some("policy denied"));
                OperationCheck { allowed: false, reason: "policy denied".into() }
            }
            OperationPolicy::Log => {
                self.record_operation(operation, true, None);
                OperationCheck { allowed: true, reason: "logged".into() }
            }
            OperationPolicy::RateLimit => {
                let recent: usize = self.operations.iter().rev().take(10).filter(|o| o.operation == operation).count();
                if recent >= 3 {
                    self.record_operation(operation, false, Some("rate limited"));
                    OperationCheck { allowed: false, reason: "rate limited".into() }
                } else {
                    self.record_operation(operation, true, None);
                    OperationCheck { allowed: true, reason: String::new() }
                }
            }
        }
    }

    /// Record an operation
    fn record_operation(&mut self, operation: &str, allowed: bool, reason: Option<&str>) {
        self.operations.push(OperationRecord { operation: operation.to_string(), allowed, timestamp: now(), blocked_reason: reason.map(|s| s.to_string()) });
        self.usage.operations += 1;
    }

    /// Track resource usage
    pub fn track_memory(&mut self, bytes: usize) { self.usage.memory_bytes += bytes; }
    pub fn track_network(&mut self) { self.usage.network_calls += 1; }
    pub fn track_output(&mut self, bytes: usize) { self.usage.output_size += bytes; }

    /// Record a fault
    pub fn record_fault(&mut self, operation: &str, error: &str, severity: FaultSeverity) {
        self.faults.push(Fault { operation: operation.to_string(), error: error.to_string(), timestamp: now(), severity, recovered: false });
    }

    /// Take a snapshot for rollback
    pub fn snapshot(&mut self, state: Vec<u8>) { self.snapshots.push(state); }

    /// Rollback to last snapshot
    pub fn rollback(&mut self) -> Option<Vec<u8>> { self.snapshots.pop() }

    /// Resource utilization percentage
    pub fn utilization(&self) -> f64 { self.usage.utilization(&self.config.limits) }

    /// Is the sandbox healthy?
    pub fn is_healthy(&self) -> bool {
        self.active && self.faults.iter().filter(|f| f.severity == FaultSeverity::Critical && !f.recovered).count() == 0
    }

    /// Fault summary
    pub fn fault_summary(&self) -> (u32, u32, u32) {
        let (warn, err, crit) = self.faults.iter().fold((0, 0, 0), |(w, e, c), f| {
            match f.severity { FaultSeverity::Warning => (w+1, e, c), FaultSeverity::Error => (w, e+1, c), FaultSeverity::Critical => (w, e, c+1) }
        });
        (warn, err, crit)
    }

    /// Summary
    pub fn summary(&self) -> String {
        let (w, e, c) = self.fault_summary();
        let allowed = self.operations.iter().filter(|o| o.allowed).count();
        let blocked = self.operations.iter().filter(|o| !o.allowed).count();
        format!("Sandbox[{}]: mode={:?}, utilization={:.0%}, ops={}/blocked={}, faults={}w/{}e/{}c, healthy={}",
            self.id, self.mode, self.utilization(), allowed, blocked, w, e, c, self.is_healthy())
    }
}

#[derive(Clone, Debug)]
pub struct OperationCheck { pub allowed: bool, pub reason: String }

fn is_write_operation(op: &str) -> bool {
    op.contains("write") || op.contains("delete") || op.contains("send") || op.contains("exec") || op.contains("modify")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_operation() {
        let mut sb = Sandbox::new("s1", "a1");
        let check = sb.check_operation("memory_alloc");
        assert!(check.allowed);
    }

    #[test]
    fn test_deny_operation() {
        let mut sb = Sandbox::new("s1", "a1");
        let check = sb.check_operation("system_exec");
        assert!(!check.allowed);
    }

    #[test]
    fn test_read_only_blocks_writes() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.config.read_only = true;
        let check = sb.check_operation("file_write");
        assert!(!check.allowed);
        let check2 = sb.check_operation("memory_alloc");
        assert!(check2.allowed); // read ops still work
    }

    #[test]
    fn test_resource_exceeded() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.config.limits.max_operations = 5;
        sb.usage.operations = 5;
        let check = sb.check_operation("anything");
        assert!(!check.allowed);
    }

    #[test]
    fn test_rate_limiting() {
        let mut sb = Sandbox::new("s1", "a1");
        for _ in 0..4 { sb.check_operation("network_post"); }
        let check = sb.check_operation("network_post");
        assert!(!check.allowed); // 4th in recent 10 → rate limited
    }

    #[test]
    fn test_fault_recording() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.record_fault("file_read", "permission denied", FaultSeverity::Error);
        assert_eq!(sb.faults.len(), 1);
        assert!(!sb.is_healthy()); // error fault
    }

    #[test]
    fn test_snapshot_rollback() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.snapshot(b"state_v1".to_vec());
        sb.snapshot(b"state_v2".to_vec());
        let rolled = sb.rollback();
        assert_eq!(rolled, Some(b"state_v2".to_vec()));
        let rolled2 = sb.rollback();
        assert_eq!(rolled2, Some(b"state_v1".to_vec()));
    }

    #[test]
    fn test_utilization() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.config.limits.max_operations = 100;
        sb.usage.operations = 80;
        assert!(sb.utilization() > 0.7);
    }

    #[test]
    fn test_resource_tracking() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.track_memory(1024);
        sb.track_network();
        sb.track_output(512);
        assert_eq!(sb.usage.memory_bytes, 1024);
        assert_eq!(sb.usage.network_calls, 1);
    }

    #[test]
    fn test_fault_summary() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.record_fault("x", "w", FaultSeverity::Warning);
        sb.record_fault("y", "e", FaultSeverity::Error);
        sb.record_fault("z", "c", FaultSeverity::Critical);
        let (w, e, c) = sb.fault_summary();
        assert_eq!((w, e, c), (1, 1, 1));
    }

    #[test]
    fn test_health_after_recovery() {
        let mut sb = Sandbox::new("s1", "a1");
        sb.record_fault("x", "error", FaultSeverity::Critical);
        assert!(!sb.is_healthy());
        sb.faults[0].recovered = true;
        assert!(sb.is_healthy());
    }
}
