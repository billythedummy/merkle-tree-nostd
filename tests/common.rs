use merkle_tree_nostd::*;

use ring::digest::{Context, Digest, SHA256};

#[derive(Clone, Copy)]
pub struct DigestWrap(Digest);

impl PartialEq for DigestWrap {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl Eq for DigestWrap {}

pub struct Sha256Context(Context);

impl Hashable for DigestWrap {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Hash for DigestWrap {}

impl Hasher<DigestWrap> for Sha256Context {
    fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> DigestWrap {
        DigestWrap(self.0.finish())
    }
}
