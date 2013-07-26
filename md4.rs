// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


use digest::Digest;

use std::uint;
use std::vec;

// Some unexported constants
static DIGEST_BUF_LEN: uint = 4u; // 4 32-bit words
static WORK_BUF_LEN: uint = 16u;  // 16 32-bit words
static DIGEST_LEN: uint = 16u;    // 128 bit
static MSG_BLOCK_LEN: uint = 64u; // 512 bit

/// Structure representing the state of an Md4 computation
pub struct Md4 {
    priv h: [u32, ..DIGEST_BUF_LEN],  // a, b, c, d
    priv len_low: u32,
    priv len_high: u32,
    priv msg_block: [u8, ..MSG_BLOCK_LEN],
    priv msg_block_idx: uint,
    priv work_buf: [u32, ..WORK_BUF_CNT],
    priv computed: bool,
}

fn add_input(st: &mut Md4, msg: &[u8]) {
    assert!((!st.computed));
    for msg.iter().advance |&element| {
        st.msg_block[st.msg_block_idx] = element;
        st.msg_block_idx += 1;
        st.len_low += 8;
        if st.len_low == 0 {
            st.len_high += 1;
            if st.len_high == 0 {
                // Message length overflow

                // FIXME: Need better failure mode (#2346)
                fail!();
            }
        }
        if st.msg_block_idx == MSG_BLOCK_LEN { 
            process_msg_block(st); 
            st.msg_block_idx = 0;
        }
    }
}

fn process_msg_block(st: &mut Md4) {
    // rotate x left by r
    fn rot(r: int, x: u32) -> u32 {
        let r = r as u32;
        (x << r) | (x >> (32u32 - r))
    }
    
    let mut x = &st.work_buf;

    // Copy msg_block to x
    let m = &st.msg_block;
    let mut x_i = 0u;
    let mut m_i = 0u;
    while x_i < 16u {
        x[x_i] = (m[m_i] as u32) 
               | (m[m_i+1u] as u32 << 8u32)
               | (m[m_i+2u] as u32 << 16u32)
               | (m[m_i+3u] as u32 << 24u32);
        x_i += 1u;
        m_i += 4u;
    }

    let mut [a, b, c, d] = st.h;

    // Round 1
    let mut i = 0u;
    while i < 16u {
        a = rot(3, a + ((b & c) | (!b & d)) + x[i]);
        i += 1u;
        d = rot(7, d + ((a & b) | (!a & c)) + x[i]);
        i += 1u;
        c = rot(11, c + ((d & a) | (!d & b)) + x[i]);
        i += 1u;
        b = rot(19, b + ((c & d) | (!c & a)) + x[i]);
        i += 1u;
    }

    // Round 2
    let mut i = 0u;
    let q = 0x5a827999u32;
    while i < 4u {
        a = rot(3, a + ((b & c) | ((b & d) | (c & d))) + x[i] + q);
        d = rot(5, d + ((a & b) | ((a & c) | (b & c))) + x[i + 4u] + q);
        c = rot(9, c + ((d & a) | ((d & b) | (a & b))) + x[i + 8u] + q);
        b = rot(13, b + ((c & d) | ((c & a) | (d & a))) + x[i + 12u] + q);
        i += 1u;
    }

    // Round 3
    let mut i = 0u;
    let q = 0x6ed9eba1u32;
    while i < 8u {
        let ii = if i > 2u { i - 3u } else { i };
        a = rot(3, a + (b ^ c ^ d) + x[ii] + q);
        d = rot(9, d + (a ^ b ^ c) + x[ii + 8u] + q);
        c = rot(11, c + (d ^ a ^ b) + x[ii + 4u] + q);
        b = rot(15, b + (c ^ d ^ a) + x[ii + 12u] + q);
        i += 2u;
    }

    // Update the buffer
    st.h[0] += a; 
    st.h[1] += b; 
    st.h[2] += c;
    st.h[3] += d;
}

fn mk_result(st: &mut Md4, rs: &mut [u8]) {
    if !st.computed { pad_msg(st); st.computed = true; }
    let mut i = 0u;
    let mut r_i = 0u;
    while i < 4u {
        let w = h[i];
        rs[r_i] = (w & 0xFFu32) as u8;
        rs[r_i+1] = ((w >> 8u32) & 0xFFu32) as u8;
        rs[r_i+2] = ((w >> 16u32) & 0xFFu32) as u8;
        rs[r_i+3] = (w >> 24u32) as u8;
        i += 1;
        r_i += 4;
    }
}

fn pad_msg_block(st: &mut Md4, len: uint) {
    st.msg_block[st.msg_block_idx] = 0x80u8;
    let mut i = st.msg_block_idx+1;
    while i < len {
        st.msg_block[i] = 0u8;
    }
}

fn pad_msg(st: &mut Md4) {
    // Pad message
    if st.msg_block_idx >= MSG_BLOCK_LEN-8 {
        // Process last batch before appending length
        pad_msg_block(st, MSG_BLOCK_LEN);
        process_msg_block(st);
    }
    if st.msg_block_idx < MSG_BLOCK_LEN-8 {
        pad_msg_block(st, MSG_BLOCK_LEN-8);
    }

    // Append length
    let mut i = 0u;
    let mut len = (st.len_high as u64) << 32u64 | (st.len_low as u64);
    while i < 8u {
        st.msg_block[MSG_BLOCK_LEN-8+i] = (len & 0xFFu64) as u8;
        len >>= 8u64;
        i += 1;
    }

    process_msg_block(st);
}

/// Calculates the md4 hash of a slice of bytes, returning the hex-encoded
/// version of the hash
pub fn md4_str(msg: &[u8]) -> ~str {
    let Md4 {a, b, c, d} = md4(msg);
    fn app(a: u32, b: u32, c: u32, d: u32, f: &fn(u32)) {
        f(a); f(b); f(c); f(d);
    }
    let mut result = ~"";
    do app(a, b, c, d) |u| {
        let mut i = 0u32;
        while i < 4u32 {
            let byte = (u >> (i * 8u32)) as u8;
            if byte <= 16u8 {
                result.push_char('0')
            }
            result.push_str(uint::to_str_radix(byte as uint, 16u));
            i += 1u32;
        }
    }
    result
}

/// Calculates the md4 hash of a string, returning the hex-encoded version of
/// the hash
pub fn md4_text(msg: &str) -> ~str { md4_str(msg.as_bytes()) }

impl Digest for Md4 {
    pub fn reset(&mut self) {
        self.h = [0x67452301u32,
                  0xefcdab89u32, 
                  0x98badcfeu32, 
                  0x10325476u32];
        self.computed = false;
    }
    pub fn input(&mut self, msg: &[u8]) { add_input(self, msg); }
    pub fn result(&mut self, out: &mut [u8]) { return mk_result(self, out); }
    pub fn output_bits(&self) -> uint { 128 }
}

#[test]
fn test_md4() {
    assert_eq!(md4_text(""), ~"31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(md4_text("a"), ~"bde52cb31de33e46245e05fbdbd6fb24");
    assert_eq!(md4_text("abc"), ~"a448017aaf21d8525fc10ae87aa6729d");
    assert!(md4_text("message digest") ==
        ~"d9130a8164549fe818874806e1c7014b");
    assert!(md4_text("abcdefghijklmnopqrstuvwxyz") ==
        ~"d79e1c308aa5bbcdeea8ed63df412da9");
    assert!(md4_text(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
        0123456789") == ~"043f8582f241db351ce627e153e7f0e4");
    assert!(md4_text("1234567890123456789012345678901234567890123456789\
                     0123456789012345678901234567890") ==
        ~"e33b4ddc9c38f2199c3e7b164fcc0536");
}
