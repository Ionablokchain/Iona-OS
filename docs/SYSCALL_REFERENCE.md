# IONA OS Syscall Reference

| Nr  | Name              | Args                        | Returns              |
|-----|-------------------|-----------------------------|----------------------|
| 0   | sys_read          | fd, buf, len                | bytes_read           |
| 1   | sys_write         | fd, buf, len                | bytes_written        |
| 2   | sys_open          | path, flags, mode           | fd                   |
| 3   | sys_close         | fd                          | 0                    |
| 4   | sys_stat          | path, stat_buf              | 0                    |
| 8   | sys_lseek         | fd, offset, whence          | offset               |
| 9   | sys_mmap          | addr, len, prot, flags, fd, off | addr             |
| 11  | sys_munmap        | addr, len                   | 0                    |
| 16  | sys_ioctl         | fd, req, arg                | 0                    |
| 17  | sys_writev        | fd, iov, iovcnt             | bytes_written        |
| 20  | sys_getpid        |                             | pid                  |
| 22  | sys_pipe          | fds_ptr                     | 0                    |
| 24  | sys_sched_yield   |                             | 0                    |
| 32  | sys_dup           | fd                          | new_fd               |
| 33  | sys_dup2          | old_fd, new_fd              | new_fd               |
| 35  | sys_nanosleep     | secs                        | 0                    |
| 37  | sys_sleep_ms      | ms                          | 0                    |
| 56  | sys_clone         | flags, stack                | pid                  |
| 57  | sys_fork          |                             | pid (0=child)        |
| 59  | sys_execve        | path, argv, envp            | 0                    |
| 60  | sys_exit          | code                        | —                    |
| 61  | sys_waitpid       | pid, status, options        | pid                  |
| 202 | sys_epoll_create  |                             | epfd                 |
| 203 | sys_epoll_ctl     | epfd, op, fd, event, data   | 0                    |
| 204 | sys_epoll_wait    | epfd, events, max, timeout  | n_events             |
| 202 | sys_futex         | uaddr, op, val, timeout     | 0/woken              |
| 300 | sys_uptime_ms     |                             | uptime               |
| 301 | sys_klog          | msg_ptr, msg_len            | 0                    |
| 302 | iona_fs_read      | path, buf, len              | bytes_read           |
| 303 | iona_fs_write     | path, buf, len              | bytes_written        |
| 310 | sys_tcp_connect   | ip, port                    | fd                   |
| 311 | sys_tcp_send      | fd, buf, len                | bytes_sent           |
| 312 | sys_tcp_recv      | fd, buf, len                | bytes_recv           |
| 400 | sys_consensus_tick| height, round, step, val_id | committed_height     |
| 401 | sys_ipc_recv      | wid, buf, len               | event_len            |
| 500 | sys_fs_snapshot   | path, path_len              | bytes                |
| 501 | sys_fs_restore    | path, path_len              | files_restored       |
| 600 | gui_create_window | title, x, y, w, h          | wid                  |
| 601 | gui_draw_pixels   | wid, x, y, w, h, pixels    | 0                    |
| 602 | gui_flush         | wid                         | 0                    |
| 603 | gui_close_window  | wid                         | 0                    |
