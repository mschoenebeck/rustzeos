# Rustzeos

This is the Rust library for easy integration of zk-SNARKs into EOS(IO) applications.

See also:
- [ZEOSIO](https://github.com/mschoenebeck/zeosio/)
- [Token Contract](https://github.com/mschoenebeck/thezeostoken/)
- [The ZEOS Book](https://mschoenebeck.github.io/zeos-orchard/) (including a full protocol specification)

## Description
This library includes all kinds of helpful functions that are necessary to get started with zk-SNARKs on the EOS mainnet. It supports custom circuit design as well as verifying key and proof creation for [Groth16](https://electriccoin.co/blog/bellman-zksnarks-in-rust/) and [Halo2](https://zcash.github.io/halo2/index.html) proving systems. Functions for Serialization/Deserialization allow for easy communication with the ZEOS [Token Contract](https://github.com/mschoenebeck/thezeostoken/) to set verifying keys and to verify proofs.

## Getting Started

To setup the full workspace clone the dependencies [bellman](https://github.com/mschoenebeck/bellman), [halo2](https://github.com/mschoenebeck/halo2) and [pasta_curves](https://github.com/mschoenebeck/pasta_curves) as well:

```
mkdir zeos
cd zeos
git clone https://github.com/mschoenebeck/bellman.git
git clone https://github.com/mschoenebeck/halo2.git
git clone https://github.com/mschoenebeck/pasta_curves.git
```

Clone this repository:

```
git clone https://github.com/mschoenebeck/rustzeos.git
cd rustzeos
```

Build the project as Rust library:

```
cargo build
```

Run the unit tests:

```
cargo test --package rustzeos --lib -- groth16::tests::test_groth16_circuit --exact --nocapture
cargo test --package rustzeos --lib -- halo2::tests::test_halo2_circuit --exact --nocapture
```

### Dependencies

- [Rust Toolchain](https://www.rust-lang.org/tools/install)

## Help
If you need help join us on [Telegram](https://t.me/ZeosOnEos)

## Authors

Matthias Schönebeck

## License

It's open source. Do with it whatever you want.

## Acknowledgments

Big thanks to the Electric Coin Company for developing, documenting and maintaining this awesome open source codebase for zk-SNARKs!

* [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)