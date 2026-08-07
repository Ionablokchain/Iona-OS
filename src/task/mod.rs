//! Task subsystem
//!
//! A task is an independent execution unit with:
//! - its own kernel stack (4 pages = 16KB)
//! - its own CPU context (callee‑saved registers)
//! - state: New, Running, Ready, Blocked, Dead
//!
//! In Phase 1: all tasks run in ring 0 (kernel space).
//! Phase 2 adds ring 3 (userspace) with syscalls.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Task Module                                   │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        stack             │
//! │ (TaskConfig)│ (TaskError)  │ (TaskId,      │ (TaskStack)              │
//! │             │              │  TaskState)   │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   task      │   manager    │   metrics     │        builder           │
//! │ (Task struct)│ (TaskManager)│ (TaskMetrics) │ (TaskBuilder)           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::task::{TaskManager, TaskConfig, TaskBuilder};
//!
//! let config = TaskConfig::default();
//! let manager = TaskManager::new(config);
//! let task = TaskBuilder::new("my_task")
//!     .with_entry(my_function)
//!     .with_arg(42)
//!     .build();
//! manager.add_task(task);
//! ```

#![allow(dead_code)]

pub mod context;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use context::Context;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the task subsystem.
    use serde::{Deserialize, Serialize};

    /// Configuration for task creation and management.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TaskConfig {
        /// Size of each task stack in bytes (default: 16KB).
        pub stack_size: usize,
        /// Stack alignment (must be power of two, default: 16 bytes).
        pub stack_alignment: usize,
        /// Whether to enable task creation logging.
        pub log_creation: bool,
        /// Whether to collect metrics.
        pub collect_metrics: bool,
        /// Whether to log state transitions.
        pub log_state_transitions: bool,
    }

    impl Default for TaskConfig {
        fn default() -> Self {
            Self {
                stack_size: 4 * 4096, // 16KB
                stack_alignment: 16,
                log_creation: true,
                collect_metrics: true,
                log_state_transitions: false,
            }
        }
    }

    impl TaskConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.stack_size == 0 || self.stack_size % 4096 != 0 {
                return Err("stack_size must be a multiple of page size (4096)");
            }
            if self.stack_alignment == 0 || !self.stack_alignment.is_power_of_two() {
                return Err("stack_alignment must be a power of two");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for task operations.
    use super::types::TaskId;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum TaskError {
        #[error("task {0} not found")]
        TaskNotFound(TaskId),

        #[error("task already running")]
        AlreadyRunning,

        #[error("task already dead")]
        AlreadyDead,

        #[error("invalid task state transition from {from:?} to {to:?}")]
        InvalidStateTransition { from: super::types::TaskState, to: super::types::TaskState },

        #[error("no idle task configured")]
        NoIdleTask,

        #[error("configuration error: {0}")]
        Config(String),

        #[error("out of memory")]
        OutOfMemory,
    }

    pub type TaskResult<T> = Result<T, TaskError>;
}

pub mod types {
    //! Task types and identifiers.
    use super::error::{TaskError, TaskResult};
    use core::fmt;

    /// Unique task ID — monotonically increasing.
    pub type TaskId = u64;

    /// Task state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskState {
        /// Newly created, never run.
        New,
        /// Currently running on the CPU.
        Running,
        /// Ready to run, in the scheduler queue.
        Ready,
        /// Blocked — waiting for an event (sleep, I/O, etc.).
        Blocked,
        /// Terminated — resources to be freed.
        Dead,
    }

    impl TaskState {
        /// Check if the task is schedulable (Ready or Running).
        pub fn is_schedulable(&self) -> bool {
            matches!(self, TaskState::Ready | TaskState::Running)
        }

        /// Check if the task is alive (not Dead).
        pub fn is_alive(&self) -> bool {
            !matches!(self, TaskState::Dead)
        }

        /// Check if the task is blocked.
        pub fn is_blocked(&self) -> bool {
            matches!(self, TaskState::Blocked)
        }
    }

    impl fmt::Display for TaskState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let s = match self {
                Self::New => "New",
                Self::Running => "Running",
                Self::Ready => "Ready",
                Self::Blocked => "Blocked",
                Self::Dead => "Dead",
            };
            write!(f, "{}", s)
        }
    }

    /// Task priority (0 = normal, 1 = high, 255 = realtime).
    pub type Priority = u8;

    /// Default priority for normal tasks.
    pub const PRIORITY_NORMAL: Priority = 0;
    /// Priority for high‑priority tasks.
    pub const PRIORITY_HIGH: Priority = 1;
    /// Priority for real‑time tasks.
    pub const PRIORITY_REALTIME: Priority = 255;
    /// Priority for the idle task.
    pub const PRIORITY_IDLE: Priority = 0;

    /// Task name (static string).
    pub type TaskName = &'static str;

    /// Task entry point type.
    pub type TaskEntry = fn(u64) -> !;

    /// Wait event type for blocked tasks.
    pub type WaitEvent = crate::sched::WaitEvent;

    /// Sleep deadline (uptime_ms).
    pub type SleepDeadline = u64;
}

pub mod stack {
    //! Task stack allocation and management.
    use super::config::TaskConfig;
    use alloc::boxed::Box;
    use core::fmt;

    /// Allocated stack for a task.
    #[repr(C, align(16))]
    pub struct TaskStack {
        data: Box<[u8]>,
        size: usize,
    }

    impl TaskStack {
        /// Allocate a new stack of the configured size.
        pub fn new(config: &TaskConfig) -> Self {
            let size = config.stack_size;
            let data = vec![0u8; size].into_boxed_slice();
            Self { data, size }
        }

        /// Get the top address of the stack (stack grows downward on x86).
        pub fn top(&self, config: &TaskConfig) -> u64 {
            let ptr = self.data.as_ptr() as u64;
            // Align to the configured alignment (default 16 bytes).
            let align = config.stack_alignment as u64;
            (ptr + self.size as u64) & !(align - 1)
        }

        /// Get the bottom address of the stack.
        pub fn bottom(&self) -> u64 {
            self.data.as_ptr() as u64
        }

        /// Get the size of the stack.
        pub fn size(&self) -> usize {
            self.size
        }
    }

    impl fmt::Debug for TaskStack {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TaskStack")
                .field("ptr", &self.data.as_ptr())
                .field("size", &self.size)
                .finish()
        }
    }
}

pub mod task {
    //! The `Task` struct and its methods.
    use super::{
        config::TaskConfig,
        types::{TaskId, TaskState, TaskName, TaskEntry, Priority, SleepDeadline, WaitEvent},
        context::Context,
        stack::TaskStack,
    };
    use core::fmt;

    /// A kernel task.
    pub struct Task {
        pub tid: TaskId,
        pub name: TaskName,
        pub state: TaskState,
        pub context: Context,
        pub priority: Priority,
        pub ticks: u64,
        pub sleep_until: Option<SleepDeadline>,
        pub wait_event: Option<WaitEvent>,
        pub stolen_at_ms: u64,
        _stack: TaskStack,
    }

    impl Task {
        /// Create a new task.
        pub fn new(
            name: TaskName,
            entry: TaskEntry,
            arg: u64,
            priority: Priority,
            tid: TaskId,
            config: &TaskConfig,
        ) -> Self {
            let stack = TaskStack::new(config);
            let stack_top = stack.top(config);
            let context = Context::new_task(stack_top, entry as u64, arg, &context::ContextConfig::default())
                .expect("failed to create task context");

            if config.log_creation {
                crate::serial_println!(
                    "[TASK] created '{}' tid={} stack_top=0x{:x}",
                    name, tid, stack_top
                );
            }

            Self {
                tid,
                name,
                state: TaskState::New,
                context,
                _stack: stack,
                priority,
                ticks: 0,
                sleep_until: None,
                wait_event: None,
                stolen_at_ms: 0,
            }
        }

        /// Create a task with a pre‑existing stack pointer (used by clone/threads).
        pub fn new_with_stack(
            name: TaskName,
            tid: TaskId,
            stack_ptr: u64,
            config: &TaskConfig,
        ) -> Self {
            let stack = TaskStack::new(config);
            if config.log_creation {
                crate::serial_println!(
                    "[TASK] created '{}' tid={} sp=0x{:x}",
                    name, tid, stack_ptr
                );
            }
            Self {
                tid,
                name,
                state: TaskState::New,
                context: Context::empty(),
                _stack: stack,
                priority: super::types::PRIORITY_NORMAL,
                ticks: 0,
                sleep_until: None,
                wait_event: None,
                stolen_at_ms: 0,
            }
        }

        /// Create the idle task (TID 0).
        pub fn new_idle(config: &TaskConfig) -> Self {
            let stack = TaskStack::new(config);
            let stack_top = stack.top(config);
            let context = Context::new_task(
                stack_top,
                super::idle_task as *const () as u64,
                0,
                &context::ContextConfig::default(),
            ).expect("failed to create idle task context");

            Self {
                tid: 0,
                name: "idle",
                state: TaskState::Ready,
                context,
                _stack: stack,
                priority: super::types::PRIORITY_IDLE,
                ticks: 0,
                sleep_until: None,
                wait_event: None,
                stolen_at_ms: 0,
            }
        }

        /// Get the task's name.
        pub fn name(&self) -> &str {
            self.name
        }

        /// Get the task's TID.
        pub fn tid(&self) -> TaskId {
            self.tid
        }

        /// Get the task's current state.
        pub fn state(&self) -> TaskState {
            self.state
        }

        /// Get the task's priority.
        pub fn priority(&self) -> Priority {
            self.priority
        }

        /// Get the task's stack top.
        pub fn stack_top(&self, config: &TaskConfig) -> u64 {
            self._stack.top(config)
        }

        /// Check if the task is the idle task.
        pub fn is_idle(&self) -> bool {
            self.tid == 0
        }

        /// Mark the task as running.
        pub fn set_running(&mut self) {
            self.state = TaskState::Running;
        }

        /// Mark the task as ready.
        pub fn set_ready(&mut self) {
            self.state = TaskState::Ready;
        }

        /// Mark the task as blocked.
        pub fn set_blocked(&mut self) {
            self.state = TaskState::Blocked;
        }

        /// Mark the task as dead.
        pub fn set_dead(&mut self) {
            self.state = TaskState::Dead;
        }

        /// Set the sleep deadline.
        pub fn set_sleep_until(&mut self, deadline: SleepDeadline) {
            self.sleep_until = Some(deadline);
            self.state = TaskState::Blocked;
        }

        /// Clear the sleep deadline (wake up).
        pub fn clear_sleep(&mut self) {
            self.sleep_until = None;
            if self.state == TaskState::Blocked {
                self.state = TaskState::Ready;
            }
        }

        /// Set the wait event.
        pub fn set_wait_event(&mut self, event: WaitEvent) {
            self.wait_event = Some(event);
            self.state = TaskState::Blocked;
        }

        /// Clear the wait event.
        pub fn clear_wait_event(&mut self) {
            self.wait_event = None;
            if self.state == TaskState::Blocked {
                self.state = TaskState::Ready;
            }
        }

        /// Increment the tick counter.
        pub fn inc_ticks(&mut self) {
            self.ticks += 1;
        }
    }

    impl fmt::Debug for Task {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Task")
                .field("tid", &self.tid)
                .field("name", &self.name)
                .field("state", &self.state)
                .field("priority", &self.priority)
                .field("ticks", &self.ticks)
                .field("sleep_until", &self.sleep_until)
                .field("stolen_at_ms", &self.stolen_at_ms)
                .finish()
        }
    }
}

pub mod builder {
    //! Fluent builder for tasks.
    use super::{
        config::TaskConfig,
        error::{TaskError, TaskResult},
        types::{TaskId, TaskName, TaskEntry, Priority, PRIORITY_NORMAL},
        task::Task,
    };
    use core::fmt;

    /// Fluent builder for `Task`.
    pub struct TaskBuilder {
        name: Option<TaskName>,
        entry: Option<TaskEntry>,
        arg: Option<u64>,
        priority: Priority,
        tid: Option<TaskId>,
    }

    impl TaskBuilder {
        pub fn new(name: TaskName) -> Self {
            Self {
                name: Some(name),
                entry: None,
                arg: None,
                priority: PRIORITY_NORMAL,
                tid: None,
            }
        }

        pub fn with_entry(mut self, entry: TaskEntry) -> Self {
            self.entry = Some(entry);
            self
        }

        pub fn with_arg(mut self, arg: u64) -> Self {
            self.arg = Some(arg);
            self
        }

        pub fn with_priority(mut self, priority: Priority) -> Self {
            self.priority = priority;
            self
        }

        pub fn with_tid(mut self, tid: TaskId) -> Self {
            self.tid = Some(tid);
            self
        }

        pub fn build(self, config: &TaskConfig) -> TaskResult<Task> {
            let name = self.name.ok_or_else(|| {
                TaskError::Config("task name not set".into())
            })?;
            let entry = self.entry.ok_or_else(|| {
                TaskError::Config("task entry not set".into())
            })?;
            let arg = self.arg.unwrap_or(0);
            let tid = self.tid.unwrap_or_else(crate::task::next_tid);

            Ok(Task::new(name, entry, arg, self.priority, tid, config))
        }
    }

    impl fmt::Debug for TaskBuilder {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TaskBuilder")
                .field("name", &self.name)
                .field("entry", &self.entry.map(|e| e as *const () as u64))
                .field("arg", &self.arg)
                .field("priority", &self.priority)
                .field("tid", &self.tid)
                .finish()
        }
    }
}

pub mod metrics {
    //! Metrics for the task subsystem.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct TaskMetrics {
        pub tasks_created: AtomicU64,
        pub tasks_destroyed: AtomicU64,
        pub tasks_running: AtomicU64,
        pub tasks_ready: AtomicU64,
        pub tasks_blocked: AtomicU64,
        pub tasks_dead: AtomicU64,
        pub context_switches: AtomicU64,
    }

    impl TaskMetrics {
        pub fn inc_created(&self) {
            self.tasks_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_destroyed(&self) {
            self.tasks_destroyed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn set_running(&self, count: u64) {
            self.tasks_running.store(count, Ordering::Relaxed);
        }
        pub fn set_ready(&self, count: u64) {
            self.tasks_ready.store(count, Ordering::Relaxed);
        }
        pub fn set_blocked(&self, count: u64) {
            self.tasks_blocked.store(count, Ordering::Relaxed);
        }
        pub fn set_dead(&self, count: u64) {
            self.tasks_dead.store(count, Ordering::Relaxed);
        }
        pub fn inc_context_switches(&self) {
            self.context_switches.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> TaskMetricsSnapshot {
            TaskMetricsSnapshot {
                tasks_created: self.tasks_created.load(Ordering::Relaxed),
                tasks_destroyed: self.tasks_destroyed.load(Ordering::Relaxed),
                tasks_running: self.tasks_running.load(Ordering::Relaxed),
                tasks_ready: self.tasks_ready.load(Ordering::Relaxed),
                tasks_blocked: self.tasks_blocked.load(Ordering::Relaxed),
                tasks_dead: self.tasks_dead.load(Ordering::Relaxed),
                context_switches: self.context_switches.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TaskMetricsSnapshot {
        pub tasks_created: u64,
        pub tasks_destroyed: u64,
        pub tasks_running: u64,
        pub tasks_ready: u64,
        pub tasks_blocked: u64,
        pub tasks_dead: u64,
        pub context_switches: u64,
    }
}

pub mod manager {
    //! Centralised manager for tasks.
    use super::{
        config::TaskConfig,
        error::{TaskError, TaskResult},
        types::{TaskId, TaskState},
        task::Task,
        builder::TaskBuilder,
        metrics::TaskMetrics,
    };
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use spin::Mutex;

    /// Centralised manager for task creation and tracking.
    #[derive(Debug)]
    pub struct TaskManager {
        config: TaskConfig,
        tasks: Mutex<BTreeMap<TaskId, Task>>,
        metrics: TaskMetrics,
        idle_tid: Option<TaskId>,
    }

    impl TaskManager {
        /// Create a new task manager.
        pub fn new(config: TaskConfig) -> Self {
            config.validate().unwrap_or(());
            Self {
                config,
                tasks: Mutex::new(BTreeMap::new()),
                metrics: TaskMetrics::default(),
                idle_tid: None,
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(TaskConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &TaskMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &TaskConfig {
            &self.config
        }

        /// Add a task to the manager.
        pub fn add_task(&self, mut task: Task) -> TaskResult<TaskId> {
            let tid = task.tid;
            if task.tid == 0 && task.name == "idle" {
                self.idle_tid = Some(tid);
            }
            let mut tasks = self.tasks.lock();
            if tasks.contains_key(&tid) {
                return Err(TaskError::TaskNotFound(tid));
            }
            tasks.insert(tid, task);
            self.metrics.inc_created();
            self.update_state_counters(&tasks);
            Ok(tid)
        }

        /// Remove a dead task and free its resources.
        pub fn remove_task(&self, tid: TaskId) -> TaskResult<()> {
            let mut tasks = self.tasks.lock();
            if let Some(task) = tasks.remove(&tid) {
                self.metrics.inc_destroyed();
                self.update_state_counters(&tasks);
                Ok(())
            } else {
                Err(TaskError::TaskNotFound(tid))
            }
        }

        /// Get a task by TID.
        pub fn get_task(&self, tid: TaskId) -> Option<Task> {
            let tasks = self.tasks.lock();
            tasks.get(&tid).cloned()
        }

        /// Get a mutable reference to a task by TID.
        pub fn get_task_mut(&self, tid: TaskId) -> Option<impl FnOnce(&mut Task)> {
            let mut tasks = self.tasks.lock();
            if let Some(task) = tasks.get_mut(&tid) {
                Some(|f: &mut dyn FnMut(&mut Task)| f(task))
            } else {
                None
            }
        }

        /// Update task state (e.g., mark as running).
        pub fn set_task_state(&self, tid: TaskId, state: TaskState) -> TaskResult<()> {
            let mut tasks = self.tasks.lock();
            let task = tasks.get_mut(&tid).ok_or(TaskError::TaskNotFound(tid))?;
            if self.config.log_state_transitions {
                crate::serial_println!(
                    "[TASK] TID={} {} -> {}",
                    tid, task.state, state
                );
            }
            task.state = state;
            self.update_state_counters(&tasks);
            Ok(())
        }

        /// Mark a task as running (for the scheduler).
        pub fn set_running(&self, tid: TaskId) -> TaskResult<()> {
            self.set_task_state(tid, TaskState::Running)
        }

        /// Mark a task as ready.
        pub fn set_ready(&self, tid: TaskId) -> TaskResult<()> {
            self.set_task_state(tid, TaskState::Ready)
        }

        /// Mark a task as blocked.
        pub fn set_blocked(&self, tid: TaskId) -> TaskResult<()> {
            self.set_task_state(tid, TaskState::Blocked)
        }

        /// Mark a task as dead.
        pub fn set_dead(&self, tid: TaskId) -> TaskResult<()> {
            self.set_task_state(tid, TaskState::Dead)
        }

        /// Get all tasks.
        pub fn all_tasks(&self) -> Vec<Task> {
            let tasks = self.tasks.lock();
            tasks.values().cloned().collect()
        }

        /// Get all task IDs.
        pub fn all_tids(&self) -> Vec<TaskId> {
            let tasks = self.tasks.lock();
            tasks.keys().copied().collect()
        }

        /// Get the number of tasks.
        pub fn task_count(&self) -> usize {
            let tasks = self.tasks.lock();
            tasks.len()
        }

        /// Get the idle task ID.
        pub fn idle_tid(&self) -> Option<TaskId> {
            self.idle_tid
        }

        /// Update state counters.
        fn update_state_counters(&self, tasks: &BTreeMap<TaskId, Task>) {
            let mut running = 0;
            let mut ready = 0;
            let mut blocked = 0;
            let mut dead = 0;

            for task in tasks.values() {
                match task.state {
                    TaskState::Running => running += 1,
                    TaskState::Ready => ready += 1,
                    TaskState::Blocked => blocked += 1,
                    TaskState::Dead => dead += 1,
                    _ => {}
                }
            }

            self.metrics.set_running(running);
            self.metrics.set_ready(ready);
            self.metrics.set_blocked(blocked);
            self.metrics.set_dead(dead);
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::TaskConfig;
pub use error::{TaskError, TaskResult};
pub use types::{TaskId, TaskState, Priority, TaskName, TaskEntry};
pub use task::Task;
pub use builder::TaskBuilder;
pub use metrics::{TaskMetrics, TaskMetricsSnapshot};
pub use manager::TaskManager;

pub use context::{Context, ContextConfig, ContextBuilder};

// -----------------------------------------------------------------------------
// Global constants and functions (kept for backward compatibility)
// -----------------------------------------------------------------------------

/// Task stack size (legacy constant).
pub const TASK_STACK_SIZE: usize = 4 * 4096; // 16KB

/// Unique task ID counter.
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Generate the next task ID.
pub fn next_tid() -> TaskId {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

/// Initialize the task subsystem (legacy).
pub fn init() {
    crate::serial_println!("  [TASK] subsystem initialized");
}

/// The idle task — runs when no other task is ready.
pub fn idle_task(_arg: u64) -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_entry(_arg: u64) -> ! {
        loop {}
    }

    #[test]
    fn test_task_creation() {
        let config = TaskConfig::default();
        let tid = next_tid();
        let task = Task::new("test_task", dummy_entry, 42, 0, tid, &config);
        assert_eq!(task.tid, tid);
        assert_eq!(task.name, "test_task");
        assert_eq!(task.state, TaskState::New);
        assert_eq!(task.priority, 0);
    }

    #[test]
    fn test_task_state_transition() {
        let config = TaskConfig::default();
        let tid = next_tid();
        let mut task = Task::new("test", dummy_entry, 0, 0, tid, &config);
        task.set_running();
        assert_eq!(task.state, TaskState::Running);
        task.set_ready();
        assert_eq!(task.state, TaskState::Ready);
        task.set_blocked();
        assert_eq!(task.state, TaskState::Blocked);
        task.set_dead();
        assert_eq!(task.state, TaskState::Dead);
    }

    #[test]
    fn test_builder() {
        let config = TaskConfig::default();
        let task = TaskBuilder::new("builder_test")
            .with_entry(dummy_entry)
            .with_arg(100)
            .with_priority(1)
            .build(&config)
            .unwrap();
        assert_eq!(task.name, "builder_test");
        assert_eq!(task.priority, 1);
    }

    #[test]
    fn test_manager_add_and_get() {
        let manager = TaskManager::default();
        let config = TaskConfig::default();
        let tid = next_tid();
        let task = Task::new("manager_test", dummy_entry, 0, 0, tid, &config);
        manager.add_task(task).unwrap();
        let got = manager.get_task(tid).unwrap();
        assert_eq!(got.tid, tid);
        assert_eq!(got.name, "manager_test");
    }

    #[test]
    fn test_manager_remove() {
        let manager = TaskManager::default();
        let config = TaskConfig::default();
        let tid = next_tid();
        let task = Task::new("remove_test", dummy_entry, 0, 0, tid, &config);
        manager.add_task(task).unwrap();
        assert_eq!(manager.task_count(), 1);
        manager.remove_task(tid).unwrap();
        assert_eq!(manager.task_count(), 0);
    }

    #[test]
    fn test_idle_task() {
        let config = TaskConfig::default();
        let idle = Task::new_idle(&config);
        assert_eq!(idle.tid, 0);
        assert_eq!(idle.name, "idle");
        assert_eq!(idle.state, TaskState::Ready);
    }
}
