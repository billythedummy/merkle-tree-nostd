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
