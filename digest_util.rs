pub trait DigestUtilUtil {
    fn digest(&mut self, in: &[u8], out: &mut [u8]);
    fn digest_str(&mut self, in: &str, out: &mut [u8]);
    fn hex_digest(&mut self, in: &[u8]) -> ~str;
    fn hex_digest_str(&mut self, in: &str) -> ~str;
}

impl DigestUtilUtil for DigestUtil {
    fn digest(&mut self, in: &[u8], out: &mut [u8]) {
        self.input(in);
        self.result(out);
        self.reset();
    }

    fn digest_str(&mut self, in: &str, out: &mut [u8]) {
        self.input_str(in);
        self.result(out);
        self.reset();
    }

    fn hex_digest(&mut self, in: &[u8]) -> ~str {
        self.input(in);
        let result = self.result_str();
        self.reset();
        result
    }

    fn hex_digest_str(&mut self, in: &str) -> ~str {
        self.input_str(in);
        let result = self.result_str();
        self.reset();
        result
    }
}

// Usage

fn main() {
    // DigestUtil
    let sh = ~Sha1::new();
    sh.input(array);
    sh.result(output);

    // ... some time later
    sh.reset();
    sh.input(another_array);
    let digest = sh.result_str();

    // *VS*

    // DigestUtilUtil
    let sh = ~Sha1::new();
    sh.digest(array, output);

    // ... some time later
    let digest = sh.hex_digest(another_array);
}
