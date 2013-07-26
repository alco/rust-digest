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
            // Message length overflow

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
    use digest::{Digest, DigestUtil};
    use sha1::Sha1;

    #[deriving(Clone)]
    struct Test {
        input: ~str,
        output: ~[u8],
        output_str: ~str,
    }

    #[test]
    fn test() {
        fn a_million_letter_a() -> ~str {
            let mut i = 0;
            let mut rs = ~"";
            while i < 100000 {
                rs.push_str("aaaaaaaaaa");
                i += 1;
            }
            return rs;
        }
        // Test messages from FIPS 180-1
        let fips_180_1_tests = ~[
            Test {
                input: ~"",
                output: ~[
                    0xA9u8, 0x99u8, 0x3Eu8, 0x36u8,
                    0x47u8, 0x06u8, 0x81u8, 0x6Au8,
                    0xBAu8, 0x3Eu8, 0x25u8, 0x71u8,
                    0x78u8, 0x50u8, 0xC2u8, 0x6Cu8,
                ],
                output_str: ~"31d6cfe0d16ae931b73c59d7e0c089c0",
            },
            Test {
                input: ~"a",
                output: ~[
                    0xA9u8, 0x99u8, 0x3Eu8, 0x36u8,
                    0x47u8, 0x06u8, 0x81u8, 0x6Au8,
                    0xBAu8, 0x3Eu8, 0x25u8, 0x71u8,
                    0x78u8, 0x50u8, 0xC2u8, 0x6Cu8,
                ],
                output_str: ~"bde52cb31de33e46245e05fbdbd6fb24",
            },
            Test {
                input: ~"abc",
                output: ~[
                    0xA9u8, 0x99u8, 0x3Eu8, 0x36u8,
                    0x47u8, 0x06u8, 0x81u8, 0x6Au8,
                    0xBAu8, 0x3Eu8, 0x25u8, 0x71u8,
                    0x78u8, 0x50u8, 0xC2u8, 0x6Cu8,
                ],
                output_str: ~"a448017aaf21d8525fc10ae87aa6729d",
            },
            Test {
                input:
                     ~"message digest",
                output: ~[
                    0x84u8, 0x98u8, 0x3Eu8, 0x44u8,
                    0x1Cu8, 0x3Bu8, 0xD2u8, 0x6Eu8,
                    0xBAu8, 0xAEu8, 0x4Au8, 0xA1u8,
                    0xF9u8, 0x51u8, 0x29u8, 0xE5u8,
                ],
                output_str: ~"d9130a8164549fe818874806e1c7014b",
            },
            Test {
                input:
                     ~"abcdefghijklmnopqrstuvwxyz",
                output: ~[
                    0x84u8, 0x98u8, 0x3Eu8, 0x44u8,
                    0x1Cu8, 0x3Bu8, 0xD2u8, 0x6Eu8,
                    0xBAu8, 0xAEu8, 0x4Au8, 0xA1u8,
                    0xF9u8, 0x51u8, 0x29u8, 0xE5u8,
                ],
                output_str: ~"d79e1c308aa5bbcdeea8ed63df412da9",
            },
            Test {
                input:
                     ~"ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
                      "abcdefghijklmnopqrstuvwxyz" +
                      "0123456789",
                output: ~[
                    0x84u8, 0x98u8, 0x3Eu8, 0x44u8,
                    0x1Cu8, 0x3Bu8, 0xD2u8, 0x6Eu8,
                    0xBAu8, 0xAEu8, 0x4Au8, 0xA1u8,
                    0xF9u8, 0x51u8, 0x29u8, 0xE5u8,
                ],
                output_str: ~"043f8582f241db351ce627e153e7f0e4",
            },
            Test {
                input:
                     ~"123456789012345678901234567890" +
                      "123456789012345678901234567890" +
                      "12345678901234567890",
                output: ~[
                    0x84u8, 0x98u8, 0x3Eu8, 0x44u8,
                    0x1Cu8, 0x3Bu8, 0xD2u8, 0x6Eu8,
                    0xBAu8, 0xAEu8, 0x4Au8, 0xA1u8,
                    0xF9u8, 0x51u8, 0x29u8, 0xE5u8,
                ],
                output_str: ~"e33b4ddc9c38f2199c3e7b164fcc0536",
            },
            Test {
                input: a_million_letter_a(),
                output: ~[
                    0x34u8, 0xAAu8, 0x97u8, 0x3Cu8,
                    0xD4u8, 0xC4u8, 0xDAu8, 0xA4u8,
                    0xF6u8, 0x1Eu8, 0xEBu8, 0x2Bu8,
                    0xDBu8, 0xADu8, 0x27u8, 0x31u8,
                ],
                output_str: ~"34aa973cd4c4daa4f61eeb2bdbad2731",
            },
        ];
        // Examples from wikipedia

        let wikipedia_tests = ~[
            Test {
                input: ~"The quick brown fox jumps over the lazy dog",
                output: ~[
                    0x2fu8, 0xd4u8, 0xe1u8, 0xc6u8,
                    0x7au8, 0x2du8, 0x28u8, 0xfcu8,
                    0xedu8, 0x84u8, 0x9eu8, 0xe1u8,
                    0xbbu8, 0x76u8, 0xe7u8, 0x39u8,
                    0x1bu8, 0x93u8, 0xebu8, 0x12u8,
                ],
                output_str: ~"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            },
            Test {
                input: ~"The quick brown fox jumps over the lazy cog",
                output: ~[
                    0xdeu8, 0x9fu8, 0x2cu8, 0x7fu8,
                    0xd2u8, 0x5eu8, 0x1bu8, 0x3au8,
                    0xfau8, 0xd3u8, 0xe8u8, 0x5au8,
                    0x0bu8, 0xd1u8, 0x7du8, 0x9bu8,
                    0x10u8, 0x0du8, 0xb4u8, 0xb3u8,
                ],
                output_str: ~"de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
            },
        ];
        let tests = fips_180_1_tests + wikipedia_tests;

        // Test that it works when accepting the message all at once

        let mut out = [0u8, ..16];

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
            assert_eq!(out_str.len(), 40);
            assert!(out_str == t.output_str);

            md.reset();
        }
    }
}
