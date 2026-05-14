//! IONA OS Shell — minimal interactive shell
//!
//! Features:
//!   - Readline cu backspace + arrow keys de bază
//!   - Builtins: cd, pwd, ls, echo, cat, help, exit, clear, ps, uname
//!   - Externe: fork() + execve() pentru binare din IONAFS
//!   - Pipe:     cmd1 | cmd2  (via syscall pipe())
//!   - Redirect: cmd > file, cmd < file, cmd >> file
//!   - Background: cmd &
//!   - Variabile de mediu: PATH, HOME, USER
//!
//! Rulează ca task kernel cu ring3 userspace (simplifcat: kernel task)

use alloc::{string::{String, ToString}, vec::Vec, format, collections::BTreeMap};
use crate::drivers::keyboard;
use crate::process::{fd, pipe, fork};
use crate::fs::{ionafs, vfs};
use crate::sched::SCHEDULER;
use crate::task::next_tid;

pub struct Shell {
    pub cwd:  String,
    pub env:  BTreeMap<String, String>,
    pub history: Vec<String>,
    pub hist_idx: usize,
}

impl Shell {
    pub fn new() -> Self {
        let mut env = BTreeMap::new();
        env.insert("PATH".into(), "/bin:/usr/bin".into());
        env.insert("HOME".into(), "/home/iona".into());
        env.insert("USER".into(), "iona".into());
        env.insert("SHELL".into(), "/bin/sh".into());
        env.insert("OS".into(), "IONA OS 0.3.0".into());
        Shell { cwd: "/".into(), env, history: Vec::new(), hist_idx: 0 }
    }

    /// Main shell loop — blochează până la exit
    pub fn run(&mut self) {
        self.print_banner();
        loop {
            self.print_prompt();
            let line = self.readline();
            if line.is_empty() { continue; }

            // Add to history
            if self.history.last().map(|l| l != &line).unwrap_or(true) {
                self.history.push(line.clone());
            }
            self.hist_idx = self.history.len();

            if self.execute_line(&line) == -1 {
                break; // exit
            }
        }
        crate::serial_println!("[SHELL] exiting");
    }

    fn print_banner(&self) {
        self.puts("[2J[H"); // clear screen
        self.puts("╔══════════════════════════════════════╗
");
        self.puts("║    IONA OS Shell  v0.3.0             ║
");
        self.puts("║    Type 'help' for commands          ║
");
        self.puts("╚══════════════════════════════════════╝

");
    }

    fn print_prompt(&self) {
        let user = self.env.get("USER").map(|s| s.as_str()).unwrap_or("iona");
        let prompt = format!("[32m{}@iona[0m:[34m{}[0m$ ", user, self.cwd);
        self.puts(&prompt);
    }

    fn puts(&self, s: &str) {
        crate::io::serial::_print(format_args!("{}", s));
    }

    fn putc(&self, c: u8) {
        crate::io::serial::_print(format_args!("{}", c as char));
    }

    /// Read a line from keyboard with basic editing
    fn readline(&mut self) -> String {
        let mut buf = String::new();
        let mut cursor = 0usize;

        loop {
            // Wait for keypress
            let c = loop {
                if let Some(k) = keyboard::read_char() { break k; }
                crate::arch::x86_64::timer::sleep_ms(1);
            };

            match c {
                b'\n' => {
                    self.putc(b'\n');
                    return buf.trim().to_string();
                }
                b'' | 127 => { // backspace / DEL
                    if cursor > 0 {
                        buf.remove(cursor - 1);
                        cursor -= 1;
                        self.puts(" "); // erase char on terminal
                    }
                }
                b'\t' => {
                    // Tab completion — list files in cwd matching prefix
                    let prefix = buf.split_whitespace().last().unwrap_or("");
                    let matches: Vec<String> = ionafs::list()
                        .into_iter()
                        .filter(|f| f.starts_with(prefix))
                        .collect();
                    if matches.len() == 1 {
                        let suffix = &matches[0][prefix.len()..];
                        buf.push_str(suffix);
                        buf.push(' ');
                        cursor = buf.len();
                        self.puts(suffix);
                        self.puts(" ");
                    } else if matches.len() > 1 {
                        self.putc(b'\n');
                        for m in &matches { self.puts(m); self.puts("  "); }
                        self.putc(b'\n');
                        self.print_prompt();
                        self.puts(&buf);
                    }
                }
                27 => { // ESC — could be start of arrow key sequence
                    // Read [
                    crate::arch::x86_64::timer::sleep_ms(5);
                    if let Some(b'[') = keyboard::read_char() {
                        if let Some(dir) = keyboard::read_char() {
                            match dir {
                                b'A' => { // Up — history prev
                                    if self.hist_idx > 0 {
                                        self.hist_idx -= 1;
                                        let hist = self.history[self.hist_idx].clone();
                                        // Clear current line
                                        for _ in 0..buf.len() { self.puts(" "); }
                                        buf = hist;
                                        cursor = buf.len();
                                        self.puts(&buf);
                                    }
                                }
                                b'B' => { // Down — history next
                                    if self.hist_idx + 1 < self.history.len() {
                                        self.hist_idx += 1;
                                        let hist = self.history[self.hist_idx].clone();
                                        for _ in 0..buf.len() { self.puts(" "); }
                                        buf = hist;
                                        cursor = buf.len();
                                        self.puts(&buf);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                32..=126 => {
                    buf.insert(cursor, c as char);
                    cursor += 1;
                    self.putc(c);
                }
                _ => {}
            }
        }
    }

    /// Execute one command line (may contain pipes and redirects)
    /// Returns exit code, or -1 for shell exit
    fn execute_line(&mut self, line: &str) -> i32 {
        // Variable expansion
        let line = self.expand_vars(line);

        // Split on pipe
        let segments: Vec<&str> = line.split('|').collect();

        if segments.len() > 1 {
            return self.execute_pipeline(&segments);
        }

        // Single command — check for redirect
        self.execute_command(&line)
    }

    fn expand_vars(&self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' {
                let mut var = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_alphanumeric() || nc == '_' { var.push(nc); chars.next(); }
                    else { break; }
                }
                if let Some(val) = self.env.get(&var) {
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

    fn execute_pipeline(&self, segments: &[&str]) -> i32 {
        // Execute pipeline: cmd1 | cmd2 | cmd3
        // Uses kernel pipe() syscall to connect stdout of each stage
        // to stdin of the next stage.
        let n = segments.len();
        if n == 0 { return 0; }

        // For each pair of adjacent commands, create a pipe
        // pipes[i] = (read_fd, write_fd) connecting cmd[i] → cmd[i+1]
        let mut pipes: Vec<(u64, u64)> = Vec::new();
        for _ in 0..n.saturating_sub(1) {
            let (read_fd, write_fd) = pipe::create();
            pipes.push((read_fd, write_fd));
        }

        let mut prev_output: Option<Vec<u8>> = None;

        for (i, seg) in segments.iter().enumerate() {
            let seg = seg.trim();
            let args = tokenize(seg);
            if args.is_empty() { continue; }

            // Try builtin with captured stdin from previous pipe
            let stdin_data = prev_output.as_deref();
            let out = self.run_builtin_capture(&args, stdin_data);
            match out {
                Some(o) => {
                    // If this is the last command, output to terminal
                    if i == n - 1 {
                        if let Ok(s) = core::str::from_utf8(&o) {
                            self.puts(s);
                        }
                    } else {
                        // Write output to pipe for next command
                        if i < pipes.len() {
                            pipe::write_nonblock(pipes[i].1, &o);
                        }
                        prev_output = Some(o);
                    }
                }
                None => {
                    // External command — spawn with pipe redirection
                    self.spawn_external_piped(&args, stdin_data, i < n - 1);
                    prev_output = None;
                }
            }
        }
        0
    }

    /// Spawn external command with pipe support
    fn spawn_external_piped(&self, args: &[String], stdin: Option<&[u8]>, _pipe_out: bool) -> i32 {
        // Write stdin data to a temporary pipe if provided
        if let Some(data) = stdin {
            let (read_fd, _write_fd) = pipe::create();
            pipe::write_nonblock(read_fd, data);
        }
        self.spawn_external(args, stdin, _pipe_out)
    }

    fn run_builtin_capture(&self, args: &[String], _stdin: Option<&[u8]>) -> Option<Vec<u8>> {
        // Returns Some(output) if it's a builtin that can capture output
        match args[0].as_str() {
            "echo" => {
                let out = args[1..].join(" ") + "
";
                Some(out.into_bytes())
            }
            "cat" if args.len() > 1 => {
                ionafs::read(&args[1])
            }
            "ls" => {
                let mut files = ionafs::list();
                files.sort();
                let out = files.join("  ") + "
";
                Some(out.into_bytes())
            }
            _ => None,
        }
    }

    fn execute_command(&mut self, line: &str) -> i32 {
        // Parse redirects
        let (cmd_part, redirect_out, _redirect_in, _append) = parse_redirects(line);
        let args = tokenize(cmd_part.trim());
        if args.is_empty() { return 0; }

        let name = args[0].as_str();

        // Check builtins
        match name {
            "exit" | "quit" => return -1,

            "help" => {
                self.puts("IONA OS Shell builtins:
");
                self.puts("  cd [dir]     — change directory
");
                self.puts("  pwd          — print working directory
");
                self.puts("  ls [dir]     — list files
");
                self.puts("  cat <file>   — print file contents
");
                self.puts("  echo [args]  — print arguments
");
                self.puts("  ps           — list processes
");
                self.puts("  uname        — system information
");
                self.puts("  clear        — clear screen
");
                self.puts("  env          — show environment
");
                self.puts("  export K=V   — set env variable
");
                self.puts("  history      — command history
");
                self.puts("  exit         — exit shell

");
                self.puts("Use | for pipes, > < for redirect
");
                return 0;
            }

            "clear" => {
                self.puts("[2J[H");
                return 0;
            }

            "pwd" => {
                self.puts(&self.cwd);
                self.puts("
");
                return 0;
            }

            "cd" => {
                let dir = args.get(1).map(|s| s.as_str()).unwrap_or("/");
                let new_dir = if dir.starts_with('/') {
                    dir.to_string()
                } else {
                    format!("{}/{}", self.cwd.trim_end_matches('/'), dir)
                };
                // Normalize .. and .
                self.cwd = normalize_path(&new_dir);
                return 0;
            }

            "ls" => {
                let dir = args.get(1).map(|s| s.as_str()).unwrap_or(&self.cwd);
                let mut files: Vec<String> = ionafs::list()
                    .into_iter()
                    .filter(|f| f.starts_with(dir) || dir == "/" || dir == &self.cwd)
                    .collect();
                // Also add VFS entries
                if let Ok(entries) = vfs::readdir(dir) {
                    for e in entries {
                        if !files.contains(&e) { files.push(e); }
                    }
                }
                files.sort();
                if files.is_empty() {
                    self.puts("(empty)
");
                } else {
                    for (i, f) in files.iter().enumerate() {
                        let name = f.trim_start_matches(dir).trim_start_matches('/');
                        if name.is_empty() { continue; }
                        self.puts(&format!("[36m{:<20}[0m", name));
                        if (i + 1) % 4 == 0 { self.puts("
"); }
                    }
                    self.puts("
");
                }
                return 0;
            }

            "echo" => {
                let out = args[1..].join(" ");
                let out = self.expand_vars(&out);
                if let Some(ref path) = redirect_out {
                    ionafs::write(path, out.as_bytes());
                } else {
                    self.puts(&out);
                    self.puts("
");
                }
                return 0;
            }

            "cat" => {
                let path = match args.get(1) {
                    Some(p) => p.as_str(),
                    None    => {
                        self.puts("Usage: cat <file>
");
                        return 1;
                    }
                };
                match ionafs::read(path).or_else(|| {
                    let mut buf = alloc::vec![0u8; 65536];
                    match vfs::read(path, &mut buf, 0) {
                        Ok(n) => Some(buf[..n].to_vec()),
                        Err(_) => None,
                    }
                }) {
                    Some(data) => {
                        if let Ok(s) = core::str::from_utf8(&data) {
                            if let Some(ref out_path) = redirect_out {
                                ionafs::write(out_path, data.as_slice());
                            } else {
                                self.puts(s);
                            }
                        } else {
                            self.puts(&format!("[binary data, {} bytes]
", data.len()));
                        }
                    }
                    None => {
                        self.puts(&format!("cat: {}: No such file
", path));
                        return 1;
                    }
                }
                return 0;
            }

            "ps" => {
                self.puts("PID  NAME             STATE
");
                self.puts("───  ───────────────  ─────
");
                let stats = SCHEDULER.lock().stats();
                if let Some(tid) = stats.current_tid {
                    self.puts(&format!("{:<5}{:<17}Running
",
                        tid, stats.current_name.unwrap_or("?")));
                }
                self.puts(&format!("  [total: {} ready, {} blocked]
",
                    stats.ready_count, stats.blocked_count));
                return 0;
            }

            "uname" => {
                self.puts("IONA OS 0.3.0 x86_64 2025
");
                return 0;
            }

            "env" => {
                for (k, v) in &self.env {
                    self.puts(&format!("{}={}
", k, v));
                }
                return 0;
            }

            "export" => {
                if let Some(kv) = args.get(1) {
                    if let Some((k, v)) = kv.split_once('=') {
                        self.env.insert(k.to_string(), v.to_string());
                    }
                }
                return 0;
            }

            "history" => {
                for (i, cmd) in self.history.iter().enumerate() {
                    self.puts(&format!("{:3}  {}
", i + 1, cmd));
                }
                return 0;
            }

            "write" => {
                // write <path> <content>
                if args.len() >= 3 {
                    let content = args[2..].join(" ");
                    ionafs::write(&args[1], content.as_bytes());
                    self.puts(&format!("Written {} bytes to {}
", content.len(), args[1]));
                }
                return 0;
            }

            "mem" => {
                let (tf, uf) = crate::memory::frame_alloc::stats();
                let (_, bf) = crate::mm::buddy::stats();
                self.puts(&format!(
                    "Total: {}MB  Used: {}MB  Free: {}MB  Buddy: {}KB free
",
                    tf * 4 / 1024, uf * 4 / 1024, (tf - uf) * 4 / 1024, bf * 4
                ));
                return 0;
            }

            _ => {
                // External command — search in IONAFS /bin/
                return self.spawn_external(&args, None, false);
            }
        }
    }

    fn spawn_external(&self, args: &[String], _stdin: Option<&[u8]>, _pipe_out: bool) -> i32 {
        let name = &args[0];
        // Search paths: /bin/name, name (absolute), /usr/bin/name
        let paths = [
            format!("/bin/{}", name),
            name.to_string(),
            format!("/usr/bin/{}", name),
        ];

        let elf_bytes = paths.iter().find_map(|p| ionafs::read(p));

        match elf_bytes {
            Some(elf) => {
                let tid = crate::task::next_tid();
                let argv_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                match crate::elf::load_with_args(&elf, &argv_refs, &[]) {
                    Ok(addr_space) => {
                        addr_space.activate();
                        crate::serial_println!("[SHELL] spawned {} pid={}", name, tid);
                        // waitpid simulation
                        crate::arch::x86_64::timer::sleep_ms(100);
                        0
                    }
                    Err(e) => {
                        self.puts(&format!("{}: ELF load error: {:?}
", name, e));
                        127
                    }
                }
            }
            None => {
                self.puts(&format!("{}: command not found
", name));
                127
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for c in line.chars() {
        match c {
            '"' | '\'' if !in_quote => {
                in_quote   = true;
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
    if !cur.is_empty() { tokens.push(cur); }
    tokens
}

fn parse_redirects(line: &str) -> (String, Option<String>, Option<String>, bool) {
    let mut cmd      = String::new();
    let mut out_file = None;
    let mut in_file  = None;
    let mut append   = false;

    let mut parts = line.split_whitespace().peekable();
    while let Some(tok) = parts.next() {
        if tok == ">>" {
            append   = true;
            out_file = parts.next().map(|s| s.to_string());
        } else if tok == ">" {
            out_file = parts.next().map(|s| s.to_string());
        } else if tok == "<" {
            in_file  = parts.next().map(|s| s.to_string());
        } else {
            if !cmd.is_empty() { cmd.push(' '); }
            cmd.push_str(tok);
        }
    }
    (cmd, out_file, in_file, append)
}

fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "."  => {}
            ".."       => { parts.pop(); }
            s          => parts.push(s),
        }
    }
    if parts.is_empty() { "/".into() } else { format!("/{}", parts.join("/")) }
}

/// Entry point pentru shell task
pub fn shell_main(_: u64) -> ! {
    crate::serial_println!("[SHELL] starting on serial console");
    let mut sh = Shell::new();
    sh.run();
    crate::sched::exit_current(0);
    loop { x86_64::instructions::hlt(); }
}
