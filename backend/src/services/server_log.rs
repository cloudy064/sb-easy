//! In-memory ring buffer of the panel's *own* recent log lines, exposed at
//! `/api/system/logs`. This is the server's own logs — distinct from a device's
//! sing-box logs (which the agent relays via telemetry). A tracing writer tees
//! formatted lines here in addition to stdout.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

const CAP: usize = 1000;

pub type LogBuffer = Arc<Mutex<VecDeque<String>>>;

pub fn new_buffer() -> LogBuffer {
    Arc::new(Mutex::new(VecDeque::with_capacity(CAP)))
}

/// Recent server log lines, oldest first.
pub fn lines(buf: &LogBuffer) -> Vec<String> {
    buf.lock().map(|q| q.iter().cloned().collect()).unwrap_or_default()
}

/// A `tracing` MakeWriter that tees each formatted event to stdout *and* the
/// ring buffer (one entry per line).
#[derive(Clone)]
pub struct MakeTee {
    pub buf: LogBuffer,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeTee {
    type Writer = TeeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter { buf: self.buf.clone(), line: Vec::new() }
    }
}

pub struct TeeWriter {
    buf: LogBuffer,
    line: Vec<u8>,
}

impl io::Write for TeeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let _ = io::Write::write_all(&mut io::stdout(), data);
        for &b in data {
            if b == b'\n' {
                if let Ok(s) = String::from_utf8(std::mem::take(&mut self.line)) {
                    if let Ok(mut q) = self.buf.lock() {
                        if q.len() >= CAP {
                            q.pop_front();
                        }
                        q.push_back(s);
                    }
                }
            } else {
                self.line.push(b);
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut io::stdout())
    }
}
