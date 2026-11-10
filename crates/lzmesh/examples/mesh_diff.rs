// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Differential check with Apple's libcompression as the reference.
//!
//!   mesh_diff [--mutations N] [--slice BYTES] [--levels -2,0,6] [--rust-enc] files...
//!
//! Decoders: Apple vs Rust (the contract) and Apple vs C (informational), on
//! Apple-encoded streams, our streams and random mutations of both.
//! Encoders (--rust-enc): Apple must decode every Rust stream to the input;
//! Rust vs C stream bytes are reported as a porting check.
//! macOS only.

#[cfg(target_os = "macos")]
mod apple {
use std::os::raw::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

use lzmesh::{Error, Level, Params};

#[link(name = "compression")]
unsafe extern "C" {
    fn compression_encode_buffer(dst: *mut u8, dst_size: usize, src: *const u8, src_size: usize, scratch: *mut c_void, algorithm: u32) -> usize;
    fn compression_decode_buffer(dst: *mut u8, dst_size: usize, src: *const u8, src_size: usize, scratch: *mut c_void, algorithm: u32) -> usize;
}
const LZMESH: u32 = 0xE05;

fn apple_encode(src: &[u8]) -> Vec<u8> {
    let mut dst = vec![0u8; src.len() + src.len() / 8 + 4096];
    // SAFETY: buffers valid for their lengths; NULL scratch is allowed.
    let n = unsafe { compression_encode_buffer(dst.as_mut_ptr(), dst.len(), src.as_ptr(), src.len(), std::ptr::null_mut(), LZMESH) };
    assert!(n != 0 || src.is_empty());
    dst.truncate(n);
    dst
}

/// Some(bytes) on success; 0 from Apple is failure unless the stream is empty.
fn apple_decode(src: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut dst = vec![0u8; cap];
    // SAFETY: buffers valid for their lengths; NULL scratch is allowed.
    let n = unsafe { compression_decode_buffer(dst.as_mut_ptr(), dst.len(), src.as_ptr(), src.len(), std::ptr::null_mut(), LZMESH) };
    dst.truncate(n);
    (n > 0).then_some(dst)
}

#[derive(Debug)]
enum Out {
    Ok(Vec<u8>),
    Small,
    Bad,
    Panic,
}

fn ours(f: fn(&mut [u8], &[u8]) -> Result<usize, Error>, src: &[u8], cap: usize) -> Out {
    let mut dst = vec![0u8; cap];
    match catch_unwind(AssertUnwindSafe(|| f(&mut dst, src))) {
        Ok(Ok(n)) => {
            dst.truncate(n);
            Out::Ok(dst)
        }
        Ok(Err(Error::OutputTooSmall { .. })) => Out::Small,
        Ok(Err(_)) => Out::Bad,
        Err(_) => Out::Panic,
    }
}

#[derive(Default)]
struct Tally {
    cases: usize,
    agree_ok: usize,
    agree_bad: usize,
    cap: usize,
    we_accept_apple_refuses: usize,
    apple_accepts_we_refuse: usize,
    bytes_differ: usize,
    panics: usize,
}

impl Tally {
    /// Classifies `o` against Apple's answer `a` for the same bytes. An empty
    /// successful decode counts as agreeing with Apple's 0.
    fn add(&mut self, a: &Option<Vec<u8>>, o: &Out, cap: usize, label: &str, verbose: bool) {
        self.cases += 1;
        match (a, o) {
            (_, Out::Panic) => {
                self.panics += 1;
                eprintln!("PANIC {label}");
            }
            (Some(x), Out::Ok(y)) if x == y => self.agree_ok += 1,
            (Some(_), Out::Ok(_)) => {
                self.bytes_differ += 1;
                if verbose {
                    eprintln!("BYTES {label}");
                }
                dump("bytes", label, cur_stream());
            }
            (None, Out::Ok(y)) if y.is_empty() => self.agree_ok += 1,
            // "Too small" is a refusal too; Apple has no separate code for it.
            (None, Out::Bad) | (None, Out::Small) => self.agree_bad += 1,
            (Some(x), Out::Small) if x.len() == cap => self.cap += 1,
            (None, Out::Ok(_)) => {
                self.we_accept_apple_refuses += 1;
                if verbose {
                    eprintln!("WE-ACCEPT {label}");
                }
                dump("we-accept", label, cur_stream());
            }
            (Some(_), _) => {
                self.apple_accepts_we_refuse += 1;
                if verbose {
                    eprintln!("APPLE-ACCEPTS {label}");
                }
                dump("apple-accepts", label, cur_stream());
            }
        }
    }

    fn line(&self, name: &str) -> String {
        format!(
            "{name}: cases={} agree_ok={} agree_bad={} cap={} we_accept/apple_refuses={} apple_accepts/we_refuse={} bytes_differ={} panics={}",
            self.cases, self.agree_ok, self.agree_bad, self.cap, self.we_accept_apple_refuses, self.apple_accepts_we_refuse, self.bytes_differ, self.panics
        )
    }

    fn hard_failures(&self) -> usize {
        self.bytes_differ + self.panics + self.apple_accepts_we_refuse
    }
}

thread_local! {
    static CUR: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn set_stream(s: &[u8]) {
    CUR.with(|c| *c.borrow_mut() = s.to_vec());
}
fn cur_stream() -> Vec<u8> {
    CUR.with(|c| c.borrow().clone())
}
/// Writes a disagreeing stream to $MESH_DUMP/<kind>-<n>.bin when set.
fn dump(kind: &str, label: &str, s: Vec<u8>) {
    if let Ok(dir) = std::env::var("MESH_DUMP") {
        let name = label.rsplit('/').next().unwrap_or("x").replace(['@', '.'], "_");
        let file = format!("{dir}/{kind}-{}-{name}.bin", label.len());
        std::fs::write(&file, s).unwrap();
        eprintln!("  dumped {file}");
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, s: &[u8]) -> Vec<u8> {
    let mut t = s.to_vec();
    if t.is_empty() {
        return t;
    }
    match rng.below(5) {
        0 => {
            let i = rng.below(t.len());
            t[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(t.len());
            t[i] = rng.next() as u8;
        }
        2 => t.truncate(rng.below(t.len())),
        3 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(t.len());
                t[i] = rng.next() as u8;
            }
        }
        _ => {
            let a = rng.below(t.len());
            let b = rng.below(t.len());
            let n = rng.below(48).min(t.len() - a.max(b));
            t.copy_within(a..a + n, b);
        }
    }
    t
}

pub fn main() {
    let mut files = Vec::new();
    let mut mutations = 100usize;
    let mut slice = usize::MAX;
    let mut levels: Vec<i32> = vec![-2, 0, 3, 5, 6, 8];
    let mut rust_enc = false;
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--mutations" => mutations = args.next().unwrap().parse().unwrap(),
            "--slice" => slice = args.next().unwrap().parse().unwrap(),
            "--levels" => levels = args.next().unwrap().split(',').map(|x| x.parse().unwrap()).collect(),
            "--rust-enc" => rust_enc = true,
            "-v" => verbose = true,
            _ => files.push(a),
        }
    }

    let mut rng = Rng(0x2545F4914F6CDD1D);
    let (mut rust, mut c) = (Tally::default(), Tally::default());
    let (mut enc_streams, mut enc_apple_fail, mut enc_identical, mut c_enc_fail) = (0usize, 0usize, 0usize, 0usize);

    for path in &files {
        eprintln!("FILE {path}");
        let mut raw = std::fs::read(path).unwrap();
        raw.truncate(slice);
        let cap = raw.len() * 2 + 65536;
        let mut streams: Vec<(String, Vec<u8>)> = vec![(format!("{path}@apple"), apple_encode(&raw))];
        for &l in &levels {
            let p = Params::for_level(Level(l));
            eprintln!("  level {l}");
            let cs = lzmesh::compress_with(&raw, &p).ok();
            if cs.is_none() {
                c_enc_fail += 1;
                eprintln!("C-ENC-FAIL {path}@{l}");
            }
            if rust_enc {
                let rs = match lzmesh::native::compress_with(&raw, &p) {
                    Ok(rs) => rs,
                    Err(e) => {
                        enc_apple_fail += 1;
                        eprintln!("RUST-ENC-FAIL {path}@{l}: {e}");
                        continue;
                    }
                };
                enc_streams += 1;
                if Some(&rs) == cs.as_ref() {
                    enc_identical += 1;
                } else if verbose {
                    eprintln!("ENC-DIFF {path}@{l}: rust {} bytes, c {} bytes", rs.len(), cs.as_ref().map_or(0, |c| c.len()));
                }
                if apple_decode(&rs, cap).as_deref() != Some(&raw[..]) && !raw.is_empty() {
                    enc_apple_fail += 1;
                    eprintln!("ENC-APPLE-FAIL {path}@{l}");
                }
                streams.push((format!("{path}@rust{l}"), rs));
            }
            if let Some(cs) = cs {
                streams.push((format!("{path}@c{l}"), cs));
            }
        }
        for (label, s) in &streams {
            set_stream(s);
            let a = apple_decode(s, cap);
            rust.add(&a, &ours(lzmesh::native::decompress_into, s, cap), cap, label, true);
            c.add(&a, &ours(lzmesh::decompress_into, s, cap), cap, label, false);
            for m in 0..mutations {
                let t = mutate(&mut rng, s);
                set_stream(&t);
                let a = apple_decode(&t, cap);
                let lab = format!("{label}/mut{m}");
                rust.add(&a, &ours(lzmesh::native::decompress_into, &t, cap), cap, &lab, verbose);
                c.add(&a, &ours(lzmesh::decompress_into, &t, cap), cap, &lab, false);
            }
        }
    }
    println!("{}", rust.line("rust-vs-apple"));
    println!("{}", c.line("c-vs-apple   "));
    if rust_enc {
        println!("encoder: rust streams={enc_streams} rust_fail_or_apple_rejects={enc_apple_fail} identical_to_c={enc_identical} c_encoder_failures={c_enc_fail}");
    }
    std::process::exit(if rust.hard_failures() == 0 && enc_apple_fail == 0 { 0 } else { 1 });
}
}

#[cfg(target_os = "macos")]
fn main() {
    apple::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this example needs Apple's libcompression and only runs on macOS");
}
