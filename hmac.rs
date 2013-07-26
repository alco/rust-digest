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

pub struct Hmac {
    priv key: ~[u8],
    priv hash: ~Digest,
    priv computed: bool,
}

fn hash_len(self: &Hmac) -> uint {
    self.hash.output_bits() / 8
}

fn adjust_key(key: &[u8], hash: &Digest) -> ~[u8] {
    let hash_len = hash.output_bits()/8;

    if key.len() > hash_len {
        let mut buf = ~[0u8, ..hash_len];
        hash.input(key);
        hash.result(buf);
        hash.reset();
        key = buf;
    } else {
        let diff = hash_len - key.len();
        let i = 0;
        while i < diff {
            key.append(0u8);
            i += 1;
        }
    }

    return key;
}

fn reset(self: &mut Hmac) {
    let pad_inner = xor_bytes(self.key, [0x36u8, ..self.hash_len()]);
    self.hash.reset();
    self.hash.input(pad_inner);
    self.computed = false;
}

impl Hmac {
    pub fn new(key: &[u8], hash: ~Digest) -> Hmac {
        let key = adjust_key(key, &hash);
        let hmac = Hmac{key: key, hash: hash};
        hmac.reset();
        hmac
    }
}

impl Digest for Hmac {
    pub fn reset(&mut self) { reset(self); }
    pub fn input(&mut self, msg: &[u8]) { self.hash.input(msg); }

    pub fn result(&mut self, out: &mut [u8]) { 
        if !self.computed {
            let h_out = [u8];
            self.hash.result(&h_out);
            self.hash.reset();

            let pad_outer = xor_bytes(self.key, [0x5Cu8, ..self.hash_len()]);
            self.hash.input(pad_outer);
            self.hash.input(h_out); 

            self.computed = true;
        }
        self.hash.result(out);
    }

    pub fn output_bits(&self) -> uint { self.hash_inner.output_bits() }
}
