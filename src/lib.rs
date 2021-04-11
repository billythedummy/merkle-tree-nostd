//! Merkle Tree top module

#![no_std]

use core::marker::PhantomData;
use core::mem::MaybeUninit;

pub trait Hash: Sized + Copy + Hashable + Eq {}

pub trait Hashable {
    fn as_bytes(&self) -> &[u8];
}

impl<T> Hashable for T
where
    T: AsRef<[u8]>,
{
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Hashes arbitrary bytes to hash of type H
pub trait Hasher<H: Hash> {
    fn new() -> Self;

    /// ingest data to continue hashing
    fn update(&mut self, data: &[u8]);

    /// Consumes self and outputs the final hash
    fn finish(self) -> H;
}

/// Note N is total number of nodes in tree, not number of leaves
/// TODO: change to number of leaves when stable rust allows const ops on const generics
pub struct MerkleTree<H: Hash, A: Hasher<H>, const N: usize> {
    // static array containing the tree nodes (hashes)
    data: [H; N],
    _hasher_phantom: PhantomData<A>,
}

impl<H: Hash, A: Hasher<H>, const N: usize> MerkleTree<H, A, { N }> {
    /// Create a new Hash tree from a slice of Hashable data
    /// The hash of each element in `slice` form the leaf nodes
    pub fn from_slice<T: Hashable>(slice: &[T]) -> Result<Self, Error> {
        let n_leaves = slice.len();
        if !n_leaves.is_power_of_two() {
            return Err(Error::NotPowOf2 { n: N });
        }
        let cap = n_leaves * 2 - 1;
        if cap != N {
            return Err(Error::SizeMismatch {
                required: N,
                requested: cap,
            });
        }

        let mut res = Self {
            data: unsafe { MaybeUninit::uninit().assume_init() },
            _hasher_phantom: PhantomData,
        };
        // Create leaf nodes
        for (i, a) in slice.iter().enumerate() {
            let mut hasher = A::new();
            hasher.update(a.as_bytes());
            res.data[res.leaf_i(i)] = hasher.finish();
        }
        // Create rest of nodes
        let iters = n_leaves.trailing_zeros();
        for itr in 0..iters {
            let subtree_leaves = n_leaves / 2usize.pow(itr);
            let subtree_start_i = subtree_leaves - 1;
            let subtree_end_i = subtree_start_i + subtree_leaves;
            for i in (subtree_start_i..subtree_end_i).step_by(2) {
                let mut hasher = A::new();
                hasher.update(res.data[i].as_bytes());
                hasher.update(res.data[i + 1].as_bytes());
                res.data[res.parent_i(i)] = hasher.finish();
            }
        }

        Ok(res)
    }

    /// Verifies the integrity of data block of index `data_i`
    pub fn verify<T: Hashable>(&self, data: T, data_i: usize) -> Result<bool, Error> {
        let mut hasher = A::new();
        hasher.update(data.as_bytes());
        let mut hash = hasher.finish();

        let verifier = self.verifier(data_i)?;
        for (sibling_hash, sibling_direction) in verifier {
            let mut hasher = A::new();
            match sibling_direction {
                SiblingDirection::Left => {
                    hasher.update(sibling_hash.as_bytes());
                    hasher.update(hash.as_bytes());
                }
                SiblingDirection::Right => {
                    hasher.update(hash.as_bytes());
                    hasher.update(sibling_hash.as_bytes());
                }
            }
            hash = hasher.finish();
        }
        Ok(hash == self.root())
    }

    /// Creates an iterator for the successive hashes required to verify a leaf node
    pub fn verifier(&self, data_i: usize) -> Result<MerkleTreeVerifier<H, A, N>, Error> {
        match data_i >= self.n_leaves() {
            true => Err(Error::NoSuchleaf { index: data_i }),
            false => Ok(MerkleTreeVerifier {
                i: self.leaf_i(data_i),
                tree: &self,
                _hasher_phantom: PhantomData,
            }),
        }
    }

    #[inline(always)]
    pub fn root(&self) -> H {
        self.data[0]
    }

    #[inline(always)]
    pub fn n_leaves(&self) -> usize {
        (N + 1) / 2
    }

    /// Calculate index of parent node in self.data
    /// given index of child node in self.data
    #[inline(always)]
    fn parent_i(&self, i: usize) -> usize {
        (i - 1) / 2
    }

    /// Calculate index of leaf node in self.data
    /// given index of data in the data block array used to create
    #[inline(always)]
    fn leaf_i(&self, i: usize) -> usize {
        N / 2 + i
    }
}

/// verifier iterator that yields the successive hashes required to verify a leaf node
/// and enum indicating if the sibling from which the hash was retrieved was on the left or right

pub enum SiblingDirection {
    Left,
    Right,
}

pub struct MerkleTreeVerifier<'a, H: Hash, A: Hasher<H>, const N: usize> {
    /// Index of current node we're currently examining/just hashed.
    /// Initalized to index of leaf. Terminates when = 0 (so root is excluded)
    /// At each itr, returns sibling's hash and updates to parent
    i: usize,
    /// Reference to the MerkleTree we are checking against
    tree: &'a MerkleTree<H, A, { N }>,
    _hasher_phantom: PhantomData<A>,
}

impl<'a, H: Hash, A: Hasher<H>, const N: usize> Iterator for MerkleTreeVerifier<'a, H, A, { N }> {
    type Item = (H, SiblingDirection);

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == 0 {
            return None;
        }
        let (sibling_i, sibling_direction) = match self.i % 2 == 0 {
            true => (self.i - 1, SiblingDirection::Left),
            false => (self.i + 1, SiblingDirection::Right),
        };
        let res = self.tree.data[sibling_i];
        self.i = self.tree.parent_i(self.i);
        Some((res, sibling_direction))
    }
}

/// Error types

#[derive(Debug)]
pub enum Error {
    NotPowOf2 { n: usize },
    SizeMismatch { required: usize, requested: usize },
    NoSuchleaf { index: usize },
}
