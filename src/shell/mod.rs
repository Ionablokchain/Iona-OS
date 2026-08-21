//! IONA OS Shell — minimal interactive shell.
//!
//! Features:
//!   - Readline with backspace + basic arrow keys.
//!   - Builtins: cd, pwd, ls, echo, cat, help, exit, clear, ps, uname.
//!   - External: fork() + execve() for binaries from IONAFS.
//!   - Pipe:     cmd1 | cmd2 (via syscall pipe()).
//!   - Redirect: cmd > file, cmd < file, cmd >> file.
//!   - Background: cmd & (stub).
//!   - Environment variables: PATH, HOME, USER.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            Shell Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (ShellCfg)  │ (ShellErr)   │ (ShellMetr)   │ (Command, Env)           │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Input     │   Parser     │   Executor    │        Manager           │
//! │ (readline)  │ (tokenize)   │ (builtins,    │ (ShellManager)           │
//! │             │              │  external)    │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::shell::{ShellManager, ShellConfig};
//!
//! let config = ShellConfig::default();
//! let mut manager = ShellManager::new(config);
//! manager.run();  // starts the interactive shell
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the shell.
    use serde::{Deserialize, Serialize};

    /// Configuration for the shell.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShellConfig {
        pub prompt_color: bool,
        pub max_history: usize,
        pub enable_tab_completion: bool,
        pub default_path: String,
        pub default_home: String,
        pub default_user: String,
        pub collect_metrics: bool,
    }

    impl Default for ShellConfig {
        fn default() -> Self {
            Self {
                prompt_color: true,
                max_history: 1000,
                enable_tab_completion: true,
                default_path: "/bin:/usr/bin".to_string(),
                default_home: "/home/iona".to_string(),
                default_user: "iona".to_string(),
                collect_metrics: true,
            }
        }
    }

    impl ShellConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_history == 0 {
                return Err("max_history must be > 0");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for the shell.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ShellError {
        #[error("command not found: {0}")]
        CommandNotFound(String),

        #[error("file not found: {0}")]
        FileNotFound(String),

        #[error("invalid command: {0}")]
        InvalidCommand(String),

        #[error("I/O error: {0}")]
        Io(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type ShellResult<T> = Result<T, ShellError>;
}

pub mod metrics {
    //! Metrics for the shell.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ShellMetrics {
        pub commands_executed: AtomicU64,
        pub builtin_executions: AtomicU64,
        pub external_executions: AtomicU64,
        pub pipeline_executions: AtomicU64,
        pub redirects: AtomicU64,
        pub tab_completions: AtomicU64,
        pub history_entries: AtomicU64,
        pub errors: AtomicU64,
    }

    impl ShellMetrics {
        pub fn inc_cmd(&self) {
            self.commands_executed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_builtin(&self) {
            self.builtin_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_external(&self) {
            self.external_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_pipeline(&self) {
            self.pipeline_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_redirect(&self) {
            self.redirects.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_tab(&self) {
            self.tab_completions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_history(&self) {
            self.history_entries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_error(&self) {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ShellMetricsSnapshot {
            ShellMetricsSnapshot {
                commands_executed: self.commands_executed.load(Ordering::Relaxed),
                builtin_executions: self.builtin_executions.load(Ordering::Relaxed),
                external_executions: self.external_executions.load(Ordering::Relaxed),
                pipeline_executions: self.pipeline_executions.load(Ordering::Relaxed),
                redirects: self.redirects.load(Ordering::Relaxed),
                tab_completions: self.tab_completions.load(Ordering::Relaxed),
                history_entries: self.history_entries.load(Ordering::Relaxed),
                errors: self.errors.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShellMetricsSnapshot {
        pub commands_executed: u64,
        pub builtin_executions: u64,
        pub external_executions: u64,
        pub pipeline_executions: u64,
        pub redirects: u64,
        pub tab_completions: u64,
        pub history_entries: u64,
        pub errors: u64,
    }
}

pub mod types {
    //! Core types for the shell.
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Command after parsing.
    #[derive(Debug, Clone)]
    pub struct Command {
        pub args: Vec<String>,
        pub input_file: Option<String>,
        pub output_file: Option<String>,
        pub append: bool,
        pub background: bool,
        pub pipe_to: Option<Vec<Command>>,
    }

    /// Environment variables.
    pub type EnvMap = BTreeMap<String, String>;

    /// Shell state.
    pub struct ShellState {
        pub cwd: String,
        pub env: EnvMap,
        pub history: Vec<String>,
        pub history_index: usize,
        pub config: super::config::ShellConfig,
    }

    impl ShellState {
        pub fn new(config: &super::config::ShellConfig) -> Self {
            let mut env = BTreeMap::new();
            env.insert("PATH".into(), config.default_path.clone());
            env.insert("HOME".into(), config.default_home.clone());
            env.insert("USER".into(), config.default_user.clone());
            env.insert("SHELL".into(), "/bin/sh".into());
            env.insert("OS".into(), "IONA OS 0.3.0".into());
            Self {
                cwd: "/".into(),
                env,
                history: Vec::with_capacity(config.max_history),
                history_index: 0,
                config: config.clone(),
            }
        }

        pub fn add_history(&mut self, line: &str) {
            if !line.is_empty() {
                if let Some(last) = self.history.last() {
                    if last == line {
                        return;
                    }
                }
                self.history.push(line.to_string());
                if self.history.len() > self.config.max_history {
                    self.history.remove(0);
                }
                self.history_index = self.history.len();
                // Update metrics if enabled.
                if self.config.collect_metrics {
                    super::metrics::global_metrics().inc_history();
                }
            }
        }
    }
}

pub mod input {
    //! Readline and keyboard input.
    use super::types::ShellState;
    use crate::drivers::keyboard;
    use crate::io::serial::{_print, print};
    use alloc::string::String;
    use core::fmt::Write;
    use tracing::trace;

    /// Read a line with basic editing.
    pub fn readline(state: &mut ShellState) -> String {
        let mut buf = String::new();
        let mut cursor = 0usize;

        loop {
            let c = loop {
                if let Some(k) = keyboard::read_char() {
                    break k;
                }
                crate::arch::x86_64::timer::sleep_ms(1);
            };

            match c {
                b'\n' => {
                    _print(format_args!("\n"));
                    return buf.trim().to_string();
                }
                b'\x08' | 127 => {
                    if cursor > 0 {
                        buf.remove(cursor - 1);
                        cursor -= 1;
                        _print(format_args!("\x08 \x08"));
                    }
                }
                b'\t' => {
                    // Tab completion.
                    super::completion::tab_complete(state, &mut buf, &mut cursor);
                }
                27 => {
                    // ESC sequence.
                    // Read '['.
                    crate::arch::x86_64::timer::sleep_ms(5);
                    if let Some(b'[') = keyboard::read_char() {
                        if let Some(dir) = keyboard::read_char() {
                            match dir {
                                b'A' => {
                                    // Up arrow.
                                    if state.history_index > 0 {
                                        state.history_index -= 1;
                                        if let Some(hist) = state.history.get(state.history_index) {
                                            // Clear current line.
                                            for _ in 0..buf.len() {
                                                _print(format_args!("\x08 \x08"));
                                            }
                                            buf = hist.clone();
                                            cursor = buf.len();
                                            _print(format_args!("{}", buf));
                                        }
                                    }
                                }
                                b'B' => {
                                    // Down arrow.
                                    if state.history_index + 1 < state.history.len() {
                                        state.history_index += 1;
                                        if let Some(hist) = state.history.get(state.history_index) {
                                            for _ in 0..buf.len() {
                                                _print(format_args!("\x08 \x08"));
                                            }
                                            buf = hist.clone();
                                            cursor = buf.len();
                                            _print(format_args!("{}", buf));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                32..=126 => {
                    if cursor == buf.len() {
                        buf.push(c as char);
                    } else {
                        buf.insert(cursor, c as char);
                    }
                    cursor += 1;
                    _print(format_args!("{}", c as char));
                }
                _ => {}
            }
        }
    }

    /// Write a string to the console.
    pub fn puts(s: &str) {
        _print(format_args!("{}", s));
    }

    /// Write a character.
    pub fn putc(c: u8) {
        _print(format_args!("{}", c as char));
    }
}

pub mod completion {
    //! Tab completion for shell.
    use super::types::ShellState;
    use crate::fs::ionafs;
    use crate::io::serial::_print;
    use alloc::string::String;
    use alloc::vec::Vec;
    use tracing::trace;

    pub fn tab_complete(state: &mut ShellState, buf: &mut String, cursor: &mut usize) {
        if !state.config.enable_tab_completion {
            return;
        }
        // Get the last word.
        let words: Vec<&str> = buf.split_whitespace().collect();
        if words.is_empty() {
            return;
        }
        let last = words.last().unwrap();
        let prefix = *last;

        // Find matches in current directory.
        let entries = ionafs::list();
        let matches: Vec<String> = entries
            .into_iter()
            .filter(|f| f.starts_with(prefix) && !f.contains('/'))
            .collect();

        if matches.len() == 1 {
            let suffix = &matches[0][prefix.len()..];
            // Replace the last word.
            let mut parts: Vec<&str> = buf.split_whitespace().collect();
            if !parts.is_empty() {
                parts.pop();
                let new_word = format!("{}{}", prefix, suffix);
                parts.push(&new_word);
                let new_buf = parts.join(" ");
                *buf = new_buf;
                *cursor = buf.len();
                // Redraw.
                for _ in 0..buf.len() { _print(format_args!("\x08 \x08")); }
                _print(format_args!("{}", buf));
            }
            super::metrics::global_metrics().inc_tab();
        } else if matches.len() > 1 {
            // Show matches.
            _print(format_args!("\n"));
            for m in &matches {
                _print(format_args!("{}  ", m));
            }
            _print(format_args!("\n"));
            // Re-print prompt and current line.
            super::prompt::print_prompt(state);
            _print(format_args!("{}", buf));
        }
    }
}

pub mod prompt {
    //! Prompt rendering.
    use super::types::ShellState;
    use crate::io::serial::_print;
    use alloc::format;

    pub fn print_prompt(state: &ShellState) {
        let user = state.env.get("USER").map(|s| s.as_str()).unwrap_or("iona");
        let cwd = &state.cwd;
        if state.config.prompt_color {
            _print(format_args!("\x1b[32m{}@iona\x1b[0m:\x1b[34m{}\x1b[0m$ ", user, cwd));
        } else {
            _print(format_args!("{}@iona:{} $ ", user, cwd));
        }
    }
}

pub mod parser {
    //! Command parsing: tokenization, redirect, pipe, variable expansion.
    use super::types::{Command, EnvMap};
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::str::SplitWhitespace;

    /// Expand environment variables in a string.
    pub fn expand_vars(s: &str, env: &EnvMap) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' {
                let mut var = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_alphanumeric() || nc == '_' {
                        var.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(val) = env.get(&var) {
                    result.push_str(val);
                } else {
                    result.push('$');
                    result.push_str(&var);
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Tokenize a command line into arguments, respecting quotes.
    pub fn tokenize(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_quote = false;
        let mut quote_char = ' ';

        for c in line.chars() {
            match c {
                '"' | '\'' if !in_quote => {
                    in_quote = true;
                    quote_char = c;
                }
                c if in_quote && c == quote_char => {
                    in_quote = false;
                }
                ' ' | '\t' if !in_quote => {
                    if !cur.is_empty() {
                        tokens.push(cur.clone());
                        cur.clear();
                    }
                }
                _ => cur.push(c),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        tokens
    }

    /// Parse a command line into a Command structure.
    pub fn parse_command(line: &str) -> Command {
        let mut args = Vec::new();
        let mut input_file = None;
        let mut output_file = None;
        let mut append = false;
        let mut background = false;
        let mut pipe_parts = Vec::new();

        // Split on pipe if present.
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() > 1 {
            // Pipeline.
            for part in parts {
                let cmd = parse_single_command(part);
                pipe_parts.push(cmd);
            }
            return Command {
                args: Vec::new(),
                input_file: None,
                output_file: None,
                append: false,
                background: false,
                pipe_to: Some(pipe_parts),
            };
        }

        // No pipe: parse single command.
        let mut cmd = parse_single_command(line);
        // Check for background '&'.
        if let Some(last) = cmd.args.last() {
            if last == "&" {
                cmd.args.pop();
                cmd.background = true;
            }
        }
        cmd
    }

    fn parse_single_command(line: &str) -> Command {
        let mut args = Vec::new();
        let mut input_file = None;
        let mut output_file = None;
        let mut append = false;

        let mut parts = line.split_whitespace().peekable();
        while let Some(tok) = parts.next() {
            if tok == ">>" {
                append = true;
                output_file = parts.next().map(|s| s.to_string());
            } else if tok == ">" {
                output_file = parts.next().map(|s| s.to_string());
            } else if tok == "<" {
                input_file = parts.next().map(|s| s.to_string());
            } else {
                args.push(tok.to_string());
            }
        }
        Command {
            args,
            input_file,
            output_file,
            append,
            background: false,
            pipe_to: None,
        }
    }
}

pub mod builtins {
    //! Built-in shell commands.
    use super::{
        types::{ShellState, Command},
        error::{ShellError, ShellResult},
        input::puts,
        metrics::global_metrics,
        parser::expand_vars,
    };
    use crate::fs::{ionafs, vfs};
    use crate::sched::SCHEDULER;
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };
    use core::str::from_utf8;

    pub fn execute(
        cmd: &Command,
        state: &mut ShellState,
        stdin_data: Option<&[u8]>,
    ) -> ShellResult<Option<Vec<u8>>> {
        if cmd.args.is_empty() {
            return Ok(None);
        }

        let name = &cmd.args[0];
        let args = &cmd.args[1..];

        match name.as_str() {
            "exit" | "quit" => {
                // Special: return a marker to exit shell.
                return Err(ShellError::InvalidCommand("exit".into()));
            }

            "help" => {
                let text = "\
IONA OS Shell builtins:
  cd [dir]     — change directory
  pwd          — print working directory
  ls [dir]     — list files
  cat <file>   — print file contents
  echo [args]  — print arguments
  ps           — list processes
  uname        — system information
  clear        — clear screen
  env          — show environment
  export K=V   — set env variable
  history      — command history
  exit         — exit shell

Use | for pipes, > < for redirect
";
                puts(text);
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "clear" => {
                puts("\x1b[2J\x1b[H");
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "pwd" => {
                puts(&state.cwd);
                puts("\n");
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "cd" => {
                let dir = args.first().map(|s| s.as_str()).unwrap_or("/");
                let new_dir = if dir.starts_with('/') {
                    dir.to_string()
                } else {
                    format!("{}/{}", state.cwd.trim_end_matches('/'), dir)
                };
                state.cwd = super::utils::normalize_path(&new_dir);
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "ls" => {
                let dir = args.first().map(|s| s.as_str()).unwrap_or(&state.cwd);
                let mut files: Vec<String> = ionafs::list()
                    .into_iter()
                    .filter(|f| f.starts_with(dir) || dir == "/" || dir == &state.cwd)
                    .collect();
                // Also add VFS entries.
                if let Ok(entries) = vfs::readdir(dir) {
                    for e in entries {
                        if !files.contains(&e) {
                            files.push(e);
                        }
                    }
                }
                files.sort();
                if files.is_empty() {
                    puts("(empty)\n");
                } else {
                    for (i, f) in files.iter().enumerate() {
                        let name = f.trim_start_matches(dir).trim_start_matches('/');
                        if name.is_empty() {
                            continue;
                        }
                        puts(&format!("\x1b[36m{:<20}\x1b[0m", name));
                        if (i + 1) % 4 == 0 {
                            puts("\n");
                        }
                    }
                    puts("\n");
                }
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "echo" => {
                let out = args.join(" ");
                let out = expand_vars(&out, &state.env);
                // Output might be redirected; handled by executor.
                // We'll return the output as bytes.
                let out_bytes = out.into_bytes();
                global_metrics().inc_builtin();
                return Ok(Some(out_bytes));
            }

            "cat" => {
                let path = args.first().ok_or(ShellError::InvalidCommand("cat requires file".into()))?;
                let data = ionafs::read(path).or_else(|| {
                    let mut buf = alloc::vec![0u8; 65536];
                    match vfs::read(path, &mut buf, 0) {
                        Ok(n) => Some(buf[..n].to_vec()),
                        Err(_) => None,
                    }
                }).ok_or_else(|| ShellError::FileNotFound(path.clone()))?;
                global_metrics().inc_builtin();
                return Ok(Some(data));
            }

            "ps" => {
                let mut out = String::new();
                out.push_str("PID  NAME             STATE\n");
                out.push_str("───  ───────────────  ─────\n");
                let stats = SCHEDULER.lock().stats();
                if let Some(tid) = stats.current_tid {
                    out.push_str(&format!("{:<5}{:<17}Running\n", tid, stats.current_name.unwrap_or("?")));
                }
                out.push_str(&format!("  [total: {} ready, {} blocked]\n",
                    stats.ready_count, stats.blocked_count));
                puts(&out);
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "uname" => {
                puts("IONA OS 0.3.0 x86_64 2025\n");
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "env" => {
                for (k, v) in &state.env {
                    puts(&format!("{}={}\n", k, v));
                }
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "export" => {
                if let Some(kv) = args.first() {
                    if let Some((k, v)) = kv.split_once('=') {
                        state.env.insert(k.to_string(), v.to_string());
                    }
                }
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "history" => {
                for (i, cmd) in state.history.iter().enumerate() {
                    puts(&format!("{:3}  {}\n", i + 1, cmd));
                }
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "write" => {
                if args.len() < 2 {
                    puts("Usage: write <path> <content>\n");
                    return Ok(None);
                }
                let path = &args[0];
                let content = args[1..].join(" ");
                ionafs::write(path, content.as_bytes());
                puts(&format!("Written {} bytes to {}\n", content.len(), path));
                global_metrics().inc_builtin();
                return Ok(None);
            }

            "mem" => {
                let (tf, uf) = crate::memory::frame_alloc::stats();
                let (_, bf) = crate::mm::buddy::stats();
                puts(&format!(
                    "Total: {}MB  Used: {}MB  Free: {}MB  Buddy: {}KB free\n",
                    tf * 4 / 1024, uf * 4 / 1024, (tf - uf) * 4 / 1024, bf * 4
                ));
                global_metrics().inc_builtin();
                return Ok(None);
            }

            _ => {
                // Not a builtin.
                return Ok(None);
            }
        }
    }
}

pub mod external {
    //! External command execution.
    use super::{
        types::{Command, ShellState},
        error::{ShellError, ShellResult},
        parser::expand_vars,
        metrics::global_metrics,
    };
    use crate::elf;
    use crate::fs::ionafs;
    use crate::task::next_tid;
    use alloc::string::String;
    use alloc::vec::Vec;

    pub fn execute(
        cmd: &Command,
        state: &mut ShellState,
        stdin_data: Option<&[u8]>,
    ) -> ShellResult<Option<Vec<u8>>> {
        let name = &cmd.args[0];
        // Search paths.
        let path_env = state.env.get("PATH").map(|s| s.as_str()).unwrap_or("/bin");
        let mut paths = Vec::new();
        for p in path_env.split(':') {
            paths.push(format!("{}/{}", p, name));
        }
        paths.push(name.clone()); // absolute path.
        let elf_bytes = paths.iter().find_map(|p| ionafs::read(p));

        match elf_bytes {
            Some(elf) => {
                let tid = next_tid();
                let argv_refs: Vec<&str> = cmd.args.iter().map(|s| s.as_str()).collect();
                match elf::load_with_args(&elf, &argv_refs, &[]) {
                    Ok(addr_space) => {
                        addr_space.activate();
                        // In a real system, we'd wait for the process.
                        // For this stub, we just sleep a bit.
                        crate::arch::x86_64::timer::sleep_ms(100);
                        global_metrics().inc_external();
                        // We have no output capture for external commands in this stub.
                        return Ok(None);
                    }
                    Err(e) => {
                        return Err(ShellError::Internal(format!("ELF load error: {:?}", e)));
                    }
                }
            }
            None => {
                return Err(ShellError::CommandNotFound(name.clone()));
            }
        }
    }
}

pub mod utils {
    //! Utility functions.
    use alloc::string::String;
    use alloc::vec::Vec;

    pub fn normalize_path(path: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        }
    }
}

pub mod executor {
    //! Command executor (builtins, external, pipelines, redirects).
    use super::{
        types::{Command, ShellState},
        error::{ShellError, ShellResult},
        builtins, external, parser,
        input::puts,
        metrics::global_metrics,
        pipe,
    };
    use crate::fs::ionafs;
    use alloc::vec::Vec;

    /// Execute a command (possibly with redirections, pipes, background).
    pub fn execute(
        cmd: &Command,
        state: &mut ShellState,
        stdin_data: Option<&[u8]>,
    ) -> ShellResult<Option<Vec<u8>>> {
        // If pipeline, handle pipeline.
        if let Some(pipe_cmds) = &cmd.pipe_to {
            return execute_pipeline(pipe_cmds, state);
        }

        // Handle redirections.
        let mut output_data = None;
        let mut input_data = stdin_data;

        // Input redirection.
        if let Some(in_file) = &cmd.input_file {
            let data = ionafs::read(in_file)
                .ok_or_else(|| ShellError::FileNotFound(in_file.clone()))?;
            input_data = Some(&data);
        }

        // Try builtins first.
        if let Some(out) = builtins::execute(cmd, state, input_data)? {
            output_data = Some(out);
        } else {
            // External command.
            external::execute(cmd, state, input_data)?;
        }

        // Output redirection.
        if let Some(out_file) = &cmd.output_file {
            if let Some(data) = &output_data {
                ionafs::write(out_file, data);
                global_metrics().inc_redirect();
            }
        } else {
            // If output data exists and not redirected, print it.
            if let Some(data) = output_data {
                if let Ok(s) = core::str::from_utf8(&data) {
                    puts(s);
                } else {
                    puts(&format!("[binary data, {} bytes]\n", data.len()));
                }
            }
        }

        Ok(None)
    }

    fn execute_pipeline(cmds: &[Command], state: &mut ShellState) -> ShellResult<Option<Vec<u8>>> {
        if cmds.is_empty() {
            return Ok(None);
        }
        global_metrics().inc_pipeline();

        let mut prev_output: Option<Vec<u8>> = None;
        let mut pipes = Vec::new();

        // Create pipes between commands.
        for i in 0..cmds.len().saturating_sub(1) {
            let (read_fd, write_fd) = pipe::create();
            pipes.push((read_fd, write_fd));
        }

        for (i, cmd) in cmds.iter().enumerate() {
            let stdin_data = if i == 0 {
                prev_output.as_deref()
            } else {
                // We should read from pipe, but for simplicity we just pass None.
                // In a real implementation, we'd set up pipe redirections.
                None
            };
            let result = execute(cmd, state, stdin_data)?;
            if i == cmds.len() - 1 {
                // Last command: output to terminal.
                if let Some(data) = result {
                    if let Ok(s) = core::str::from_utf8(&data) {
                        puts(s);
                    }
                }
            } else {
                // Write result to pipe.
                if let Some(data) = result {
                    // Write to pipe.
                    if i < pipes.len() {
                        let (_, write_fd) = pipes[i];
                        // We'd need a non-blocking write; for simplicity, we'll ignore.
                        // pipe::write_nonblock(write_fd, &data);
                    }
                }
            }
        }

        Ok(None)
    }
}

pub mod manager {
    //! Centralised shell manager.
    use super::{
        config::ShellConfig,
        error::{ShellError, ShellResult},
        types::ShellState,
        input::readline,
        prompt::print_prompt,
        parser::parse_command,
        executor::execute,
        metrics::global_metrics,
    };
    use crate::io::serial::_print;
    use tracing::{debug, info};

    /// Shell manager.
    pub struct ShellManager {
        config: ShellConfig,
        state: ShellState,
    }

    impl ShellManager {
        pub fn new(config: ShellConfig) -> Self {
            config.validate().expect("invalid ShellConfig");
            let state = ShellState::new(&config);
            Self { config, state }
        }

        pub fn with_defaults() -> Self {
            Self::new(ShellConfig::default())
        }

        pub fn config(&self) -> &ShellConfig {
            &self.config
        }

        pub fn state(&self) -> &ShellState {
            &self.state
        }

        pub fn state_mut(&mut self) -> &mut ShellState {
            &mut self.state
        }

        /// Run the interactive shell.
        pub fn run(&mut self) {
            info!("starting shell");
            self.print_banner();
            loop {
                print_prompt(&self.state);
                let line = readline(&mut self.state);
                if line.is_empty() {
                    continue;
                }
                self.state.add_history(&line);
                if self.execute_line(&line) == -1 {
                    break;
                }
            }
            _print(format_args!("\n[SHELL] exiting\n"));
        }

        fn print_banner(&self) {
            _print(format_args!("\x1b[2J\x1b[H"));
            _print(format_args!(
                "╔══════════════════════════════════════╗\n\
                 ║    IONA OS Shell  v0.3.0             ║\n\
                 ║    Type 'help' for commands          ║\n\
                 ╚══════════════════════════════════════╝\n\n"
            ));
        }

        fn execute_line(&mut self, line: &str) -> i32 {
            global_metrics().inc_cmd();

            // Parse command.
            let cmd = parse_command(line);

            // Execute.
            match execute(&cmd, &mut self.state, None) {
                Ok(_) => 0,
                Err(ShellError::InvalidCommand(_)) => -1, // exit
                Err(e) => {
                    _print(format_args!("{}: {}\n", line, e));
                    global_metrics().inc_error();
                    1
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ShellConfig;
pub use error::{ShellError, ShellResult};
pub use metrics::{ShellMetrics, ShellMetricsSnapshot};
pub use types::{Command, EnvMap, ShellState};
pub use manager::ShellManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<ShellManager> = Once::new();

/// Initialize the global shell manager with default config.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| ShellManager::with_defaults());
    crate::serial_println!("[SHELL] subsystem initialised");
}

/// Get the global manager.
fn global_manager() -> &'static ShellManager {
    GLOBAL_MANAGER.get().expect("shell not initialised")
}

/// Run the shell (legacy entry point).
pub fn shell_main(_: u64) -> ! {
    // We need to consume the manager.
    // We'll use a static mutex to hold the manager and run it.
    // For backward compatibility, we'll use a static manager and run it.
    // Since Once doesn't give mutable access, we need to work around.
    // We'll use a static mutex for the manager.
    static SHELL_MANAGER: spin::Mutex<Option<ShellManager>> = spin::Mutex::new(None);

    let mut guard = SHELL_MANAGER.lock();
    if guard.is_none() {
        *guard = Some(ShellManager::with_defaults());
    }
    let manager = guard.as_mut().unwrap();
    manager.run();
    crate::sched::exit_current(0);
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Metrics global access
// -----------------------------------------------------------------------------

/// Global metrics singleton.
static METRICS: spin::Once<ShellMetrics> = spin::Once::new();

pub(crate) fn global_metrics() -> &'static ShellMetrics {
    METRICS.get_or_init(|| ShellMetrics::default())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = ShellConfig::default();
        assert!(config.validate().is_ok());
        let mut bad = config.clone();
        bad.max_history = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_parse_simple() {
        let cmd = parser::parse_command("echo hello world");
        assert_eq!(cmd.args, vec!["echo", "hello", "world"]);
    }

    #[test]
    fn test_parse_redirect() {
        let cmd = parser::parse_command("cat file > out.txt");
        assert_eq!(cmd.args, vec!["cat", "file"]);
        assert_eq!(cmd.output_file, Some("out.txt".to_string()));
    }

    #[test]
    fn test_parse_pipe() {
        let cmd = parser::parse_command("cmd1 | cmd2");
        assert!(cmd.pipe_to.is_some());
        let pipeline = cmd.pipe_to.unwrap();
        assert_eq!(pipeline.len(), 2);
        assert_eq!(pipeline[0].args, vec!["cmd1"]);
        assert_eq!(pipeline[1].args, vec!["cmd2"]);
    }

    #[test]
    fn test_env_expansion() {
        let mut env = BTreeMap::new();
        env.insert("USER".into(), "test".into());
        let expanded = parser::expand_vars("hello $USER", &env);
        assert_eq!(expanded, "hello test");
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(utils::normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(utils::normalize_path("/a/./b"), "/a/b");
        assert_eq!(utils::normalize_path("a/b/c"), "/a/b/c");
    }
}
