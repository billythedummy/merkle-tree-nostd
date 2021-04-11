#[cfg(test)]
use merkle_tree_nostd::*;

use std::matches;

mod common;

use common::{DigestWrap, Sha256Context};

#[test]
fn test_depth_0() {
    const CAP: usize = 1;
    let mt: MerkleTree<DigestWrap, Sha256Context, CAP> =
        MerkleTree::from_slice(&["hello"]).unwrap();

    let root = b"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24";
    assert!(mt.root().as_bytes() == root.as_bytes());

    assert!(mt.verify("hello", 0).unwrap());
    assert!(matches!(
        mt.verify("hello", 1),
        Err(Error::NoSuchleaf { index: 1 })
    ));
    assert!(!mt.verify("world", 0).unwrap());
    assert!(matches!(
        mt.verify("world", 1),
        Err(Error::NoSuchleaf { index: 1 })
    ));
}

#[test]
fn test_depth_1() {
    const CAP: usize = 3;
    let mt: MerkleTree<DigestWrap, Sha256Context, CAP> =
        MerkleTree::from_slice(&["hello", "world"]).unwrap();

    let root = b"\x73\x05\xdb\x9b\x2a\xbc\xcd\x70\x6c\x25\x6d\xb3\xd9\x7e\x5f\xf4\x8d\x67\x7c\xfe\x4d\x3a\x59\x04\xaf\xb7\xda\x0e\x39\x50\xe1\xe2";
    assert!(mt.root().as_bytes() == root.as_bytes());

    assert!(mt.verify("hello", 0).unwrap());
    assert!(mt.verify("world", 1).unwrap());
    assert!(!mt.verify("hell", 0).unwrap());
    assert!(!mt.verify("orld", 1).unwrap());
}

#[test]
fn test_depth_4() {
    const CAP: usize = 31;
    let data = [
        "we",
        "ert",
        "dsf",
        "ewfc",
        "dsfassdaf",
        "fdsqwwefew",
        "eegq3rre",
        "regfsd43",
        "d43grt43r",
        "rv452fgre",
        "3214rgr25143t2rewg23453rgwr234521gt143t2g",
        "r3fwf22d",
        "rqf32534g5312f2f53gf12dere",
        "32rtegwf",
        "3rf4f43rf",
        "j875um78loj6ki7t",
    ];
    let mt: MerkleTree<DigestWrap, Sha256Context, CAP> = MerkleTree::from_slice(&data).unwrap();

    let root = b"\x6f\x52\x7e\xb5\x8e\x42\x3a\xd6\xa0\x58\x0b\xd0\x6e\xa2\xa2\x82\x6a\x3e\x5a\x8f\x73\xa2\x51\x7c\x41\x70\xa9\x35\x49\x6c\x4b\xb8";
    assert!(mt.root().as_bytes() == root.as_bytes());

    for (i, d) in data.iter().enumerate() {
        assert!(mt.verify(d, i).unwrap());
        if i + 1 < mt.n_leaves() {
            assert!(!mt.verify(d, i + 1).unwrap());
        }
    }
}

#[test]
fn test_bounds() {
    const CAP: usize = 3;
    let mut mt_res: Result<MerkleTree<DigestWrap, Sha256Context, CAP>, Error> =
        MerkleTree::from_slice(&["hello"]);
    assert!(matches!(
        mt_res,
        Err(Error::SizeMismatch {
            required: 3,
            requested: 1
        })
    ));
    mt_res = MerkleTree::from_slice(&["hello", "world", "ex"]);
    assert!(matches!(mt_res, Err(Error::NotPowOf2 { n: 3 })));
    mt_res = MerkleTree::from_slice(&["hello", "world", "ex", "4", "5", "6", "7", "8"]);
    assert!(matches!(
        mt_res,
        Err(Error::SizeMismatch {
            required: 3,
            requested: 15,
        })
    ));
}
