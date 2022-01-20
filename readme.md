
# Hashing Function Theory

Notes relating to hashing functions.

## Original Hashing Function Papers

- [md2](https://github.com/lancejpollard/hash/blob/make/paper/md2/original.pdf)
- [md4](https://github.com/lancejpollard/hash/blob/make/paper/md4/original.pdf)
- [md5](https://github.com/lancejpollard/hash/blob/make/paper/md5/original.pdf)
- [md6](https://github.com/lancejpollard/hash/blob/make/paper/md6/original.pdf)
- [ripemd160](https://github.com/lancejpollard/hash/blob/make/paper/ripemd160/original.pdf)
- [sha1](https://github.com/lancejpollard/hash/blob/make/paper/sha1/original.pdf)
- sha2
- [sha3](https://github.com/lancejpollard/hash/blob/make/paper/sha3/original.pdf)
- [blake2](https://github.com/lancejpollard/hash/blob/make/paper/blake2/original.pdf)
- [blake3](https://github.com/lancejpollard/hash/blob/make/paper/blake3/original.pdf)

## Other Resources

- https://github.com/BLAKE3-team/BLAKE3-specs
- https://en.wikipedia.org/wiki/List_of_hash_functions
- https://en.wikipedia.org/wiki/Hash_function_security_summary
- https://en.wikipedia.org/wiki/Cipher_security_summary
- https://noiseprotocol.org/noise.html
- https://github.com/noiseprotocol/sho_spec/blob/master/sho.md

## Notes

_Much from Chapter 6 of "Serious Cryptography"._

- Two types of **iterative hashing**:
  1. **Compression function**: Iterative hashing which transforms an input to a _smaller_ input (also called a **Merkle-Damgård construction**).
  2. **Sponge function**: Iterative hashing which transforms an input to a _same sized_ input (also called a **permutation based hash function**).
- All hash functions developed from the 1980s through the 2010s are based on the Merkle-Damgård (M-D) construction: MD4, MD5, SHA-1, and the SHA-2 family, as well as the lesser-known RIPEMD and Whirlpool hash functions.

## General Approach

### General Approach of Merkle-Damgård Construction

- Break message into equal sized **blocks** (commonly 512 or 1024 bits, but can be any size).
- Block length is fixed for a hash functions life.
- For the last block if not equal to standard block size:
  1. Append 1 bit.
  2. Then append a bunch of zero bits.
  3. Then encode the leftover bits size at the end.
- For example, if you hash the 8-bit string 10101010 using SHA-256, which is a hash function with 512-bit message blocks, the first and only block will appear, in bits, as follows: 101010101000000000000...000001000. The 1000 at the end of the block (underlined) is the message’s length, or 8 encoded in binary.
- If a compression function is preimage and collision resistant, then a hash function built on it using the M-D construction will also be preimage and collision
resistant.
- **Davies-Meyer Construction**: Most common block-cypher based compression functions.
- All compression functions used in real hash functions such as SHA-256 and BLAKE2 are based on block ciphers, because that is the simplest way to build a compression function.
- As long as the block cipher is secure, the resulting compression function is secure as well as collision and preimage resistant.
- There are many block cipher-based compression functions other than Davies-Meyer.
- **Sponge functions** use a single permutation instead of a compression function and a block cipher.
- Instead of using a block cipher to mix message bits with the internal state, sponge functions just do an XOR operation.
- The most famous sponge function is Keccak, also known as SHA-3.
