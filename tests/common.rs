use merkle_tree_nostd::*;

use ring::digest::{Context, Digest, SHA256};

pub struct Sha256Context(Context);

impl Hasher<Digest> for Sha256Context {
    fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> Digest {
        self.0.finish()
    }
}
