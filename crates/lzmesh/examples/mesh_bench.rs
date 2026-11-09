// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Single-thread LZMESH throughput, one engine per process.
//!
//!   mesh_bench enc <c|rust|apple> <level> <reps> files...
//!   mesh_bench dec <c|rust|apple> <c|apple> <level> <reps> files...
//!
//! `dec` decodes streams made by the C encoder at <level> (identical to the
//! Rust encoder's) or by Apple's. Reports the best and median rep in MB/s of
//! uncompressed data. macOS only (Apple engine).

use std::os::raw::c_void;
use std::time::Instant;

use lzmesh::{Level, Params};

#[link(name = "compression")]
unsafe extern "C" {
    fn compression_encode_buffer(dst: *mut u8, dst_size: usize, src: *const u8, src_size: usize, scratch: *mut c_void, algorithm: u32) -> usize;
    fn compression_decode_buffer(dst: *mut u8, dst_size: usize, src: *const u8, src_size: usize, scratch: *mut c_void, algorithm: u32) -> usize;
}
const LZMESH: u32 = 0xE05;

fn apple_enc(dst: &mut [u8], src: &[u8]) -> usize {
    // SAFETY: buffers valid for their lengths; NULL scratch is allowed.
    unsafe { compression_encode_buffer(dst.as_mut_ptr(), dst.len(), src.as_ptr(), src.len(), std::ptr::null_mut(), LZMESH) }
}

fn apple_dec(dst: &mut [u8], src: &[u8]) -> usize {
    // SAFETY: buffers valid for their lengths; NULL scratch is allowed.
    unsafe { compression_decode_buffer(dst.as_mut_ptr(), dst.len(), src.as_ptr(), src.len(), std::ptr::null_mut(), LZMESH) }
}

fn report(what: &str, total: usize, comp: usize, mut times: Vec<f64>) {
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mbs = |t: f64| total as f64 / t / 1e6;
    println!(
        "{what:<22} raw={:.1}MB saved={:.2}% best={:.1}MB/s median={:.1}MB/s",
        total as f64 / 1e6,
        100.0 * (1.0 - comp as f64 / total as f64),
        mbs(times[0]),
        mbs(times[times.len() / 2])
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (files, reps, level, engine) = match a[1].as_str() {
        "enc" => (&a[5..], a[4].parse::<usize>().unwrap(), a[3].parse::<i32>().unwrap(), a[2].as_str()),
        _ => (&a[6..], a[5].parse::<usize>().unwrap(), a[4].parse::<i32>().unwrap(), a[2].as_str()),
    };
    let raws: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    let total: usize = raws.iter().map(|r| r.len()).sum();
    let p = Params::for_level(Level(level));

    if a[1] == "enc" {
        let mut dst = vec![0u8; raws.iter().map(|r| r.len()).max().unwrap() * 2 + 65536];
        let mut times = Vec::new();
        let mut comp = 0;
        for _ in 0..reps {
            comp = 0;
            let t = Instant::now();
            for r in &raws {
                comp += match engine {
                    "c" => lzmesh::compress_with(r, &p).unwrap().len(),
                    "rust" => lzmesh::native::compress_with(r, &p).unwrap().len(),
                    _ => apple_enc(&mut dst, r),
                };
            }
            times.push(t.elapsed().as_secs_f64());
        }
        let label = if engine == "apple" { "enc apple".to_string() } else { format!("enc {engine} L{level}") };
        report(&label, total, comp, times);
    } else {
        let source = a[3].as_str();
        let streams: Vec<Vec<u8>> = raws
            .iter()
            .map(|r| {
                if source == "apple" {
                    let mut d = vec![0u8; r.len() * 2 + 65536];
                    let n = apple_enc(&mut d, r);
                    d.truncate(n);
                    d
                } else {
                    lzmesh::compress_with(r, &p).unwrap()
                }
            })
            .collect();
        let comp: usize = streams.iter().map(|s| s.len()).sum();
        let mut dst = vec![0u8; raws.iter().map(|r| r.len()).max().unwrap() + 64];
        let mut times = Vec::new();
        for _ in 0..reps {
            let t = Instant::now();
            for (r, s) in raws.iter().zip(&streams) {
                let d = &mut dst[..r.len()];
                let n = match engine {
                    "c" => lzmesh::decompress_into(d, s).unwrap(),
                    "rust" => lzmesh::native::decompress_into(d, s).unwrap(),
                    _ => apple_dec(d, s),
                };
                assert_eq!(n, r.len());
            }
            times.push(t.elapsed().as_secs_f64());
        }
        let src_label = if source == "apple" { "apple".to_string() } else { format!("L{level}") };
        report(&format!("dec {engine} ({src_label})"), total, comp, times);
    }
}
