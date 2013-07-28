// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


extern mod extra;
use extra::digest::Digest;

// Some unexported constants
static DIGEST_BUF_LEN: uint = 4u; // 4 32-bit words
static WORK_BUF_LEN: uint = 16u;  // 16 32-bit words
static MSG_BLOCK_LEN: uint = 64u; // 512 bit

/// Structure representing the state of an Md4 computation
pub struct Md4 {
    priv h: [u32, ..DIGEST_BUF_LEN],  // a, b, c, d
    priv msg_len: u64,
    priv msg_block: [u8, ..MSG_BLOCK_LEN],
    priv msg_block_idx: uint,
    priv work_buf: [u32, ..WORK_BUF_LEN],
    priv computed: bool,
}

fn add_input(st: &mut Md4, msg: &[u8]) {
    assert!((!st.computed));
    for msg.iter().advance |&element| {
        st.msg_block[st.msg_block_idx] = element;
        st.msg_block_idx += 1;
        st.msg_len += 8;
        if st.msg_len == 0 {
            // FIXME: Need better failure mode (#2346)
            fail!();
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

    let x = &mut st.work_buf;

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

    let mut a = st.h[0];
    let mut b = st.h[1];
    let mut c = st.h[2];
    let mut d = st.h[3];

    // Round 1
    // F(X,Y,Z) = XY v not(X) Z
    let mut i = 0u;
    while i < 16u {
        a = rot( 3, a + ((b & c) | (!b & d)) + x[i]);
        i += 1u;
        d = rot( 7, d + ((a & b) | (!a & c)) + x[i]);
        i += 1u;
        c = rot(11, c + ((d & a) | (!d & b)) + x[i]);
        i += 1u;
        b = rot(19, b + ((c & d) | (!c & a)) + x[i]);
        i += 1u;
    }

    // Round 2
    // G(X,Y,Z) = XY v XZ v YZ
    let mut i = 0u;
    let q = 0x5a827999u32;
    while i < 4u {
        a = rot( 3, a + ((b & c) | (b & d) | (c & d)) + x[i] + q);
        d = rot( 5, d + ((a & b) | (a & c) | (b & c)) + x[i+4u] + q);
        c = rot( 9, c + ((d & a) | (d & b) | (a & b)) + x[i+8u] + q);
        b = rot(13, b + ((c & d) | (c & a) | (d & a)) + x[i+12u] + q);
        i += 1u;
    }

    // Round 3
    // H(X,Y,Z) = X xor Y xor Z
    let mut i = 0u;
    let q = 0x6ed9eba1u32;
    while i < 8u {
        let ii = if i > 2u { i - 3u } else { i };
        a = rot( 3, a + (b ^ c ^ d) + x[ii] + q);
        d = rot( 9, d + (a ^ b ^ c) + x[ii+8u] + q);
        c = rot(11, c + (d ^ a ^ b) + x[ii+4u] + q);
        b = rot(15, b + (c ^ d ^ a) + x[ii+12u] + q);
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
        let w = st.h[i];
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
        i += 1;
    }
}

fn pad_msg(st: &mut Md4) {
    if st.msg_block_idx >= MSG_BLOCK_LEN-8 {
        // Process last block before appending length
        pad_msg_block(st, MSG_BLOCK_LEN);
        process_msg_block(st);
    }
    if st.msg_block_idx < MSG_BLOCK_LEN-8 {
        pad_msg_block(st, MSG_BLOCK_LEN-8);
    }

    // Append length
    let mut i = 0u;
    let mut len = st.msg_len;
    while i < 8u {
        st.msg_block[MSG_BLOCK_LEN-8+i] = (len & 0xFFu64) as u8;
        len >>= 8u64;
        i += 1;
    }

    process_msg_block(st);
}

impl Md4 {
    /// Construct an `md4` object
    pub fn new() -> Md4 {
        let mut st = Md4{
            h: [0u32, ..DIGEST_BUF_LEN],
            msg_len: 0u64,
            msg_block: [0u8, ..MSG_BLOCK_LEN],
            msg_block_idx: 0,
            work_buf: [0u32, ..WORK_BUF_LEN],
            computed: false,
        };
        st.reset();
        return st;
    }
}

impl Digest for Md4 {
    pub fn reset(&mut self) {
        self.h = [0x67452301u32,
                  0xefcdab89u32,
                  0x98badcfeu32,
                  0x10325476u32];
        self.msg_len = 0;
        self.msg_block_idx = 0;
        self.computed = false;
    }
    pub fn input(&mut self, msg: &[u8]) { add_input(self, msg); }
    pub fn result(&mut self, out: &mut [u8]) { mk_result(self, out); }
    pub fn output_bits(&self) -> uint { 128 } // static?
}

#[cfg(test)]
mod tests {
    use extra::digest::{Digest, DigestUtil};
    use Md4;

    #[deriving(Clone)]
    struct Test {
        input: ~str,
        output: ~[u8],
        output_str: ~str,
    }

    #[test]
    fn test() {
        let wikipedia_tests = ~[
            Test {
                input: ~"",
                output: ~[
                    0x31u8, 0xd6u8, 0xcfu8, 0xe0u8,
                    0xd1u8, 0x6au8, 0xe9u8, 0x31u8,
                    0xb7u8, 0x3cu8, 0x59u8, 0xd7u8,
                    0xe0u8, 0xc0u8, 0x89u8, 0xc0u8,
                ],
                output_str: ~"31d6cfe0d16ae931b73c59d7e0c089c0",
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy dog",
                output: ~[
                    0x1bu8, 0xeeu8, 0x69u8, 0xa4u8,
                    0x6bu8, 0xa8u8, 0x11u8, 0x18u8,
                    0x5cu8, 0x19u8, 0x47u8, 0x62u8,
                    0xabu8, 0xaeu8, 0xaeu8, 0x90u8,
                ],
                output_str: ~"1bee69a46ba811185c194762abaeae90",
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy cog",
                output: ~[
                    0xb8u8, 0x6eu8, 0x13u8, 0x0cu8,
                    0xe7u8, 0x02u8, 0x8du8, 0xa5u8,
                    0x9eu8, 0x67u8, 0x2du8, 0x56u8,
                    0xadu8, 0x01u8, 0x13u8, 0xdfu8,
                ],
                output_str: ~"b86e130ce7028da59e672d56ad0113df",
            },
        ];
        let tests = wikipedia_tests;


        let mut out = [0u8, ..16];

        // Test that it works when accepting the message all at once
        let mut md = ~Md4::new();
        for tests.iter().advance |t| {
            (*md).input_str(t.input);
            md.result(out);
            assert!(t.output.as_slice() == out);

            let out_str = (*md).result_str();
            assert_eq!(out_str.len(), 32);
            assert!(out_str == t.output_str);

            md.reset();
        }

        // Test that it works when accepting the message in pieces
        for tests.iter().advance |t| {
            let len = t.input.len();
            let mut left = len;
            while left > 0u {
                let take = (left + 1u) / 2u;
                (*md).input_str(t.input.slice(len - left, take + len - left));
                left = left - take;
            }
            md.result(out);
            assert!(t.output.as_slice() == out);

            let out_str = (*md).result_str();
            assert_eq!(out_str.len(), 32);
            assert!(out_str == t.output_str);

            md.reset();
        }
    }
}
