// xcoin-wallet — post-quantum wallet keytool for xCoin (XID).
//
// Buyer-facing companion to Mac Metal Miner. Generates and recovers the
// post-quantum keys that own your mining rewards, and prints your witness v3
// receiving address (xpa1r… mainnet, txa1r… testnet A) to paste into the miner.
//
// One seed regenerates every key:
//   ML-DSA-65 key i   seed -> SHAKE-256(seed || "NEX-PQ-MASTER") -> master (32)
//                     master -> SHAKE-256(master || u32le(i) || "NEX-PQ-CHILD") -> child (32)
//                     child is the FIPS 204 KeyGen seed (crypto_sign_keypair_from_seed);
//                     exactly the node's DerivePQKeyFromSeed (src/pqhd.cpp)
//   SLH-DSA-SHA2-128s key i   SHAKE-256(child || "xcoin/hd/slh-dsa-sha2-128s/seed") -> 48 bytes
//                     (dex-wallet-cli's convention: one position, two algorithms, distinct
//                     domains. A wallet convention, not consensus; the node's own descriptor
//                     wallet seeds from BIP32 root material under ".../seed/v2" instead)
//
// The address is the protocol-standard TWO-LEAF tree (contrib/regenesis/REGENESIS.md
// section 4, the node wallet's pqtr({pq(K),slh(K')})): {ML-DSA-65 leaf 0xc0,
// SLH-DSA-SHA2-128s fallback leaf 0xc2}. The single-leaf tree {0xc0} over the same
// key hash (the "carried" form, which earlier builds of this tool printed as the
// address) is still derived, recognized and spendable. Byte-for-byte the trees of
// dex-wallet-cli's keytool; `_v3vectors` pins them against it.
//
// Built from the node's own PQClean ML-DSA-65 and SLH-DSA-SHA2-128s sources
// (./pqcrypto), so every address and signature is consensus-valid by
// construction. The seed is the complete backup and never leaves this process.
//
// SPDX-License-Identifier: MIT

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include <CommonCrypto/CommonDigest.h>   // macOS SHA-256 (no external libs)

extern "C" {
#include "fips202.h"                     // PQClean SHAKE-256 (incremental API)
}

// PQClean ML-DSA-65 deterministic keygen + signing (from the node's own sources)
extern "C" {
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen,
        const uint8_t* m, size_t mlen, const uint8_t* sk);
    int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen,
        const uint8_t* m, size_t mlen, const uint8_t* pk);
}
// PQClean sphincs-sha2-128s-simple with the node's FIPS 205 FORS change (SLH-DSA-SHA2-128s):
// only the seeded keygen is needed here, for the 0xc2 fallback leaf of every address.
extern "C" {
    int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
}
#include <cstdlib>   // arc4random_buf — macOS CSPRNG for fresh seed generation
#include <algorithm> // std::lexicographical_compare (the sorted XCoinBranch)

using bytes = std::vector<uint8_t>;

static const size_t PQ_PK   = 1952;   // ML-DSA-65 public key bytes
static const size_t PQ_SK   = 4032;   // ML-DSA-65 secret key bytes
static const size_t PQ_SIG  = 3309;   // ML-DSA-65 signature bytes (max)
static const size_t SLH_PK   = 32;    // SLH-DSA-SHA2-128s public key
static const size_t SLH_SK   = 64;    // SLH-DSA-SHA2-128s secret key
static const size_t SLH_SEED = 48;    // SK.seed || SK.prf || PK.seed

// Must match src/pqhd.h exactly.
static const char* PQ_MASTER_DOMAIN = "NEX-PQ-MASTER";
static const char* PQ_CHILD_DOMAIN  = "NEX-PQ-CHILD";
// SLH-DSA seed domain: dex-wallet-cli's keytool convention, NOT the node's current
// DeriveXcoinSLHSeed (which uses ".../seed/v2" over BIP32 root material + path):
// SHAKE-256(child32 || domain) -> 48 bytes. Frozen: two-leaf balances on chain are paid to keys it derives.
static const char* XCOIN_HD_SLH_SEED_DOMAIN = "xcoin/hd/slh-dsa-sha2-128s/seed";
static const char* HRP              = "xpa";   // Xcoin bech32m human-readable part
static const uint8_t WITVER         = 2;       // xpa1z… = witness version 2
static const char* IDENTITY_HRP     = "xid";   // forum identity xid1…: bech32m, no witness version, not an address

// ── hex helpers ───────────────────────────────────────────────────────────────
static std::string to_hex(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 15]; }
    return s;
}
static bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

static void wipe(bytes& v) { if (!v.empty()) memset(v.data(), 0, v.size()); v.clear(); }
static bytes sha256(const bytes& d) { bytes h(32); CC_SHA256(d.data(), (CC_LONG)d.size(), h.data()); return h; }

// ── HD derivation (ML-DSA: exactly src/pqhd.cpp DerivePQKeyFromSeed; SLH: dex's) ────
// Ported from dex-wallet-cli's keytool (derive_child_seed / derive_slh_seed /
// derive_key_material), minus its Bitcoin leg.
static void shake256_domain(const uint8_t* key, size_t klen, const char* domain, uint8_t* out, size_t outlen) {
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, key, klen);
    shake256_inc_absorb(&ctx, (const uint8_t*)domain, strlen(domain));
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, outlen, &ctx);
    shake256_inc_ctx_release(&ctx);
}
// The 32-byte child secret of key index `index`; it IS the ML-DSA-65 KeyGen seed.
static bytes derive_child_seed(const bytes& seed, uint32_t index) {
    uint8_t master[32];
    shake256_domain(seed.data(), seed.size(), PQ_MASTER_DOMAIN, master, 32);   // SHAKE-256(seed || "NEX-PQ-MASTER")
    uint8_t idxLE[4] = { (uint8_t)(index & 0xFF), (uint8_t)((index >> 8) & 0xFF),
                         (uint8_t)((index >> 16) & 0xFF), (uint8_t)((index >> 24) & 0xFF) };
    bytes child(32);
    shake256incctx ctx;                                                        // SHAKE-256(master || u32le(i) || "NEX-PQ-CHILD")
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, master, 32);
    shake256_inc_absorb(&ctx, idxLE, 4);
    shake256_inc_absorb(&ctx, (const uint8_t*)PQ_CHILD_DOMAIN, strlen(PQ_CHILD_DOMAIN));
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(child.data(), 32, &ctx);
    shake256_inc_ctx_release(&ctx);
    memset(master, 0, sizeof(master));
    return child;
}
// SHAKE-256(child32 || "xcoin/hd/slh-dsa-sha2-128s/seed") -> 48 bytes (dex-wallet-cli derive_slh_seed).
static bytes derive_slh_seed(const bytes& child) {
    bytes out(SLH_SEED);
    shake256_domain(child.data(), child.size(), XCOIN_HD_SLH_SEED_DOMAIN, out.data(), out.size());
    return out;
}

struct KeyMaterial {
    bytes pq_pk, pq_sk, pq_hash;   // ML-DSA-65 key, SHA-256(pubkey)
    bytes slh_pk;                  // SLH-DSA-SHA2-128s public key (the 0xc2 leaf key)
    ~KeyMaterial() { wipe(pq_sk); }
};
// Derive both keys of index `index`. The ML-DSA secret key is kept only when
// want_secret is set. This tool never signs with SLH-DSA (the fallback leaf is for
// the node or dex-wallet-cli), so the SLH secret key is wiped as soon as it exists.
static bool derive_key_material(const bytes& seed, uint32_t index, KeyMaterial& km, bool want_secret) {
    bytes child = derive_child_seed(seed, index);
    km.pq_pk.assign(PQ_PK, 0); km.pq_sk.assign(PQ_SK, 0);
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(km.pq_pk.data(), km.pq_sk.data(), child.data());
    bytes slh_seed = derive_slh_seed(child);
    wipe(child);
    if (ret != 0) { wipe(km.pq_sk); wipe(slh_seed); return false; }
    km.pq_hash = sha256(km.pq_pk);
    km.slh_pk.assign(SLH_PK, 0);
    bytes slh_sk(SLH_SK, 0);
    ret = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_seed_keypair(km.slh_pk.data(), slh_sk.data(), slh_seed.data());
    wipe(slh_seed); wipe(slh_sk);
    if (ret != 0) { wipe(km.pq_sk); return false; }
    if (!want_secret) wipe(km.pq_sk);
    return true;
}

// ── bech32m (BIP-350) ─────────────────────────────────────────────────────────
// bech32m (BIP-350) — adapted from the reference implementation,
// Copyright (c) 2017, 2021 Pieter Wuille, MIT License (github.com/sipa/bech32).
static const char* B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint32_t polymod(const std::vector<uint8_t>& v) {
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t x : v) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ x;
        for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
static std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> r;
    for (char c : hrp) r.push_back((uint8_t)c >> 5);
    r.push_back(0);
    for (char c : hrp) r.push_back((uint8_t)c & 31);
    return r;
}
static std::vector<uint8_t> convertbits(const std::vector<uint8_t>& data) {  // 8→5, padded
    int acc = 0, bits = 0; std::vector<uint8_t> ret;
    for (uint8_t v : data) { acc = (acc << 8) | v; bits += 8; while (bits >= 5) { bits -= 5; ret.push_back((acc >> bits) & 31); } }
    if (bits) ret.push_back((acc << (5 - bits)) & 31);
    return ret;
}
// bech32m string for `hrp` over 5-bit `data` (a witness version, when there is one, is data[0]).
static std::string bech32m_encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> chk = hrp_expand(hrp);
    chk.insert(chk.end(), data.begin(), data.end());
    for (int i = 0; i < 6; i++) chk.push_back(0);
    uint32_t mod = polymod(chk) ^ 0x2bc830a3;   // bech32m constant
    std::string out = hrp + "1";
    for (uint8_t v : data) out += B32[v];
    for (int i = 0; i < 6; i++) out += B32[(mod >> (5 * (5 - i))) & 31];
    return out;
}
// Forum identity xid1…: HRP "xid", NO witness version byte, then the 32-byte
// program (SHA-256 of the public key, the same bytes the addresses commit to).
// 62 chars: "xid1" + 52 data + 6 checksum. Without a version byte and under a
// non-chain HRP no node ever parses it as an address, so nothing can be paid to
// it: it is a chat/forum handle for the key, not a place to send coins.
static std::string bech32m_identity(const std::vector<uint8_t>& prog32) {
    return bech32m_encode(IDENTITY_HRP, convertbits(prog32));
}

// ── transaction (de)serialization + BIP143 sighash (matches the node) ──────────
static void put_u32le(std::vector<uint8_t>& v, uint32_t x) { for (int i=0;i<4;i++) v.push_back((x>>(8*i))&0xFF); }
static void put_u64le(std::vector<uint8_t>& v, uint64_t x) { for (int i=0;i<8;i++) v.push_back((x>>(8*i))&0xFF); }
static void put_compact(std::vector<uint8_t>& v, uint64_t n) {
    if (n < 0xfd) v.push_back((uint8_t)n);
    else if (n <= 0xffff) { v.push_back(0xfd); v.push_back(n&0xFF); v.push_back((n>>8)&0xFF); }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); put_u32le(v,(uint32_t)n); }
    else { v.push_back(0xff); put_u64le(v,n); }
}
struct Reader {
    const uint8_t* p; const uint8_t* end; bool ok=true;
    Reader(const std::vector<uint8_t>& b): p(b.data()), end(b.data()+b.size()) {}
    uint32_t u32() { if(p+4>end){ok=false;return 0;} uint32_t x=0; for(int i=0;i<4;i++) x|=(uint32_t)p[i]<<(8*i); p+=4; return x; }
    uint64_t u64() { if(p+8>end){ok=false;return 0;} uint64_t x=0; for(int i=0;i<8;i++) x|=(uint64_t)p[i]<<(8*i); p+=8; return x; }
    uint64_t compact() {
        if(p>=end){ok=false;return 0;} uint8_t c=*p++;
        if(c<0xfd) return c;
        if(c==0xfd){ if(p+2>end){ok=false;return 0;} uint64_t x=p[0]|(p[1]<<8); p+=2; return x; }
        if(c==0xfe){ return u32(); }
        return u64();
    }
    void bytes(uint8_t* out, size_t n) { if(p+n>end){ok=false;return;} memcpy(out,p,n); p+=n; }
    std::vector<uint8_t> vec(size_t n) { std::vector<uint8_t> r(n); bytes(r.data(),n); return r; }
};
struct TxIn  { uint8_t hash[32]; uint32_t vout; std::vector<uint8_t> scriptSig; uint32_t sequence; };
struct TxOut { uint64_t value; std::vector<uint8_t> spk; };
struct Tx    { uint32_t version; std::vector<TxIn> vin; std::vector<TxOut> vout; uint32_t locktime; };

static bool parse_tx(const std::vector<uint8_t>& raw, Tx& tx) {
    Reader r(raw);
    tx.version = r.u32();
    uint64_t nin = r.compact();
    bool segwit = false;
    if (nin == 0) {                    // segwit marker 0x00, flag follows
        uint8_t flag = 0; r.bytes(&flag,1); segwit = true; nin = r.compact();
    }
    for (uint64_t i=0;i<nin && r.ok;i++) {
        TxIn in; r.bytes(in.hash,32); in.vout=r.u32();
        in.scriptSig = r.vec(r.compact()); in.sequence=r.u32();
        tx.vin.push_back(std::move(in));
    }
    uint64_t nout = r.compact();
    for (uint64_t i=0;i<nout && r.ok;i++) {
        TxOut o; o.value=r.u64(); o.spk=r.vec(r.compact()); tx.vout.push_back(std::move(o));
    }
    if (segwit) {                      // skip any existing witness stacks
        for (uint64_t i=0;i<tx.vin.size() && r.ok;i++) { uint64_t items=r.compact(); for(uint64_t j=0;j<items;j++) r.vec(r.compact()); }
    }
    tx.locktime = r.u32();
    return r.ok;
}

static void dsha256(const uint8_t* d, size_t n, uint8_t out[32]) {
    uint8_t h[32]; CC_SHA256(d,(CC_LONG)n,h); CC_SHA256(h,32,out);
}
static void dsha256(const std::vector<uint8_t>& d, uint8_t out[32]) { dsha256(d.data(), d.size(), out); }

// BIP143 sighash for input nIn. scriptCode is the witnessScript (== scriptPubKey
// for witness-v2 PQ). amount in satoshis. SIGHASH_ALL only.
static void bip143_sighash(const Tx& tx, size_t nIn, const std::vector<uint8_t>& scriptCode,
                           uint64_t amount, uint8_t out[32]) {
    std::vector<uint8_t> pre, tmp;
    uint8_t hp[32], hs[32], ho[32];
    for (auto& in : tx.vin) { tmp.insert(tmp.end(), in.hash, in.hash+32); put_u32le(tmp, in.vout); }
    dsha256(tmp, hp); tmp.clear();
    for (auto& in : tx.vin) put_u32le(tmp, in.sequence);
    dsha256(tmp, hs); tmp.clear();
    for (auto& o : tx.vout) { put_u64le(tmp, o.value); put_compact(tmp, o.spk.size()); tmp.insert(tmp.end(), o.spk.begin(), o.spk.end()); }
    dsha256(tmp, ho);

    put_u32le(pre, tx.version);
    pre.insert(pre.end(), hp, hp+32);
    pre.insert(pre.end(), hs, hs+32);
    pre.insert(pre.end(), tx.vin[nIn].hash, tx.vin[nIn].hash+32);
    put_u32le(pre, tx.vin[nIn].vout);
    put_compact(pre, scriptCode.size());
    pre.insert(pre.end(), scriptCode.begin(), scriptCode.end());
    put_u64le(pre, amount);
    put_u32le(pre, tx.vin[nIn].sequence);
    pre.insert(pre.end(), ho, ho+32);
    put_u32le(pre, tx.locktime);
    put_u32le(pre, 1);                 // nHashType = SIGHASH_ALL (int32 LE)
    dsha256(pre, out);
}

// Legacy witness-v2 address derivation was removed 2026-09-24: the live chains
// (testnet A, and mainnet at genesis) accept only witness v3 outputs, so every
// address this tool prints is v3. The v2 SIGNING path in cmd_sign remains, for
// sweeping any pre-regenesis v2 coins on private chains.

// ── witness v3: the post-quantum script tree ─────────────────────────────────
// Byte-for-byte mirror of the node: src/script/xcoin_v3.h and interpreter.cpp
// (Bip341SignatureMessage + XcoinV3TagSighash). Golden vectors from
// src/test/xcoin_v3_tests.cpp are replayed by `_v3vectors`.
static const uint8_t WITVER3        = 3;      // xpa1r… / txa1r…
static const uint8_t XCOIN_LEAF_PQ  = 0xc0;   // ML-DSA-65 leaf version
static const uint8_t XCOIN_LEAF_SLH = 0xc2;   // SLH-DSA-SHA2-128s leaf version (the fallback leaf)
static const char* TAG_LEAF           = "XCoinLeaf";
static const char* TAG_BRANCH         = "XCoinBranch";
static const char* TAG_SIGHASH_BIP341 = "TapSighash";       // step 1: the BIP-341 message
static const char* TAG_SIGHASH_V3     = "XCoinSighash/v3";  // step 2: the xCoin wrap
static const char* TAG_NOKEY          = "xcoin/v3/nokey";   // plain SHA-256, NOT tagged
static std::string g_hrp = "xpa";           // --hrp txa (or XCOIN_HRP=txa) for testnet A

static void ssha256(const uint8_t* d, size_t n, uint8_t out[32]) { CC_SHA256(d, (CC_LONG)n, out); }
static void ssha256(const std::vector<uint8_t>& d, uint8_t out[32]) { ssha256(d.data(), d.size(), out); }
// BIP-340 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
static void tagged_hash(const char* tag, const std::vector<uint8_t>& msg, uint8_t out[32]) {
    uint8_t th[32]; ssha256((const uint8_t*)tag, strlen(tag), th);
    std::vector<uint8_t> pre; pre.reserve(64 + msg.size());
    pre.insert(pre.end(), th, th + 32); pre.insert(pre.end(), th, th + 32);
    pre.insert(pre.end(), msg.begin(), msg.end());
    ssha256(pre, out);
}
// Leaf hash = TaggedHash("XCoinLeaf", leaf_version || compact(script len) || script).
// A single-leaf tree's Merkle root IS the leaf hash (the carried program).
static void v3_leaf_hash(uint8_t leaf_version, const std::vector<uint8_t>& script, uint8_t out[32]) {
    std::vector<uint8_t> m; m.push_back(leaf_version);
    put_compact(m, script.size()); m.insert(m.end(), script.begin(), script.end());
    tagged_hash(TAG_LEAF, m, out);
}
// Witness v3 address: HRP ("xpa" mainnet / "txa" testnet A), version byte 3, 32-byte program.
static std::string bech32m_address_v3(const std::string& hrp, const uint8_t prog[32]) {
    std::vector<uint8_t> data; data.push_back(WITVER3);
    std::vector<uint8_t> p(prog, prog + 32);
    for (uint8_t v : convertbits(p)) data.push_back(v);
    return bech32m_encode(hrp, data);
}

// The trees of one key index: ported from dex-wallet-cli's keytool (leaf_hash,
// branch_hash, key32_checksig_script, control_block, KeyTrees, build_trees) over
// the tagged-hash primitives above.
static bytes leaf_hash(uint8_t version, const bytes& script) {
    uint8_t h[32]; v3_leaf_hash(version, script, h); return bytes(h, h + 32);
}
// branch: tagged_hash("XCoinBranch", sorted(a, b))
static bytes branch_hash(const bytes& a, const bytes& b) {
    bytes m;
    if (std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end())) { m.insert(m.end(), a.begin(), a.end()); m.insert(m.end(), b.begin(), b.end()); }
    else { m.insert(m.end(), b.begin(), b.end()); m.insert(m.end(), a.begin(), a.end()); }
    uint8_t h[32]; tagged_hash(TAG_BRANCH, m, h); return bytes(h, h + 32);
}
// <SHA256(pubkey)> OP_CHECKSIG (the ML-DSA leaf) and <pubkey32> OP_CHECKSIG (the SLH leaf): 0x20 || key32 || 0xac
static bytes key32_checksig_script(const bytes& key32) {
    bytes s; s.push_back(0x20); s.insert(s.end(), key32.begin(), key32.end()); s.push_back(0xac); return s;
}
static bytes xcoin_v3_nokey() { bytes nk(32); ssha256((const uint8_t*)TAG_NOKEY, strlen(TAG_NOKEY), nk.data()); return nk; }
// Control block: leaf version || SHA256("xcoin/v3/nokey") [|| sibling leaf hash]: 33 bytes
// in the single-leaf tree, 65 in the two-leaf tree.
static bytes control_block(uint8_t version, const bytes* sibling) {
    bytes c; c.push_back(version); bytes nk = xcoin_v3_nokey(); c.insert(c.end(), nk.begin(), nk.end());
    if (sibling) c.insert(c.end(), sibling->begin(), sibling->end());
    return c;
}

/** Everything the two trees of one key index commit to. */
struct KeyTrees {
    bytes leaf_pq_script, leaf_slh_script;   // 34 bytes each
    bytes leaf_pq, leaf_slh;                 // leaf hashes
    bytes root2;                             // {pq, slh}: the default address program
    bytes root1;                             // {pq}: the carried single-leaf program (= leaf_pq)
    bytes control_pq2;                       // ML-DSA control block in the two-leaf tree (65 bytes)
    bytes control_pq1;                       // control block of the single-leaf tree (33 bytes)
};
static KeyTrees build_trees(const bytes& pq_hash, const bytes& slh_pk) {
    KeyTrees t;
    t.leaf_pq_script = key32_checksig_script(pq_hash);
    t.leaf_slh_script = key32_checksig_script(slh_pk);
    t.leaf_pq = leaf_hash(XCOIN_LEAF_PQ, t.leaf_pq_script);
    t.leaf_slh = leaf_hash(XCOIN_LEAF_SLH, t.leaf_slh_script);
    t.root2 = branch_hash(t.leaf_pq, t.leaf_slh);
    t.root1 = t.leaf_pq;
    t.control_pq2 = control_block(XCOIN_LEAF_PQ, &t.leaf_slh);
    t.control_pq1 = control_block(XCOIN_LEAF_PQ, nullptr);
    return t;
}
static std::string v3_address(const std::string& hrp, const bytes& prog) { return bech32m_address_v3(hrp, prog.data()); }
static std::string v3_spk_hex(const bytes& prog) { return "5320" + to_hex(prog.data(), prog.size()); }   // OP_3 <32-byte push>
// forum identity (xid1…): bech32m over SHA-256(ML-DSA pubkey), no witness version
static std::string identity_from_hash(const bytes& pq_hash) { return bech32m_identity(pq_hash); }

// ── wallet file (seed at rest) ────────────────────────────────────────────────
static std::string home_dir() {
    const char* h = getenv("HOME");
    if (h && *h) return h;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : ".";
}
static std::string default_wallet_path() { return home_dir() + "/.xcoin/wallet.seed"; }

static bool read_seed_file(const std::string& path, std::string& seedhex) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return false; }
    fclose(f);
    seedhex = buf;
    while (!seedhex.empty() && (seedhex.back() == '\n' || seedhex.back() == '\r' || seedhex.back() == ' '))
        seedhex.pop_back();
    return !seedhex.empty();
}
static bool write_seed_file(const std::string& path, const std::string& seedhex) {
    std::string dir = path.substr(0, path.find_last_of('/'));
    mkdir(dir.c_str(), 0700);
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    std::string line = seedhex + "\n";
    ssize_t w = write(fd, line.c_str(), line.size());
    close(fd);
    chmod(path.c_str(), 0600);
    return w == (ssize_t)line.size();
}

// ── CLI ───────────────────────────────────────────────────────────────────────
static const char* RED = "\033[38;5;197m", *DIM = "\033[2m", *B = "\033[1m", *R = "\033[0m", *YEL = "\033[33m";

static void banner() {
    fprintf(stderr, "%s%s┌─────────────────────────────────────────────┐\n"
                    "│  xcoin-wallet · post-quantum XID wallet     │\n"
                    "│  ML-DSA-65 · deterministic · self-custody   │\n"
                    "└─────────────────────────────────────────────┘%s\n", B, RED, R);
}
// Adapted from dex-wallet-cli's print_address_block (two-leaf address first, carried form below).
static void print_address_block(const KeyMaterial& km, const KeyTrees& t, uint32_t index) {
    const std::string addr = v3_address(g_hrp, t.root2);
    const std::string carried = v3_address(g_hrp, t.root1);
    printf("\n  %s%sYour Xcoin receiving address%s (index %u, witness v3, %s):\n", B, RED, R, index, g_hrp.c_str());
    printf("  %s%s%s%s\n\n", B, RED, addr.c_str(), R);
    printf("  %sscriptPubKey%s  %s%s%s\n", DIM, R, DIM, v3_spk_hex(t.root2).c_str(), R);
    printf("  %stree          {ML-DSA-65 leaf 0xc0, SLH-DSA-SHA2-128s fallback leaf 0xc2}%s\n", DIM, R);
    printf("  %sML-DSA key hash %s%s\n", DIM, to_hex(km.pq_hash.data(), km.pq_hash.size()).c_str(), R);
    printf("  %sSLH-DSA key     %s%s\n", DIM, to_hex(km.slh_pk.data(), km.slh_pk.size()).c_str(), R);
    printf("\n  %sSingle-leaf (carried) form of the same key, still recognized and spendable:%s\n", DIM, R);
    printf("  %s%s%s\n", DIM, carried.c_str(), R);
    printf("  %sPaste the address above into NerdMiner to receive block rewards.%s\n", DIM, R);
}
static void wipe_reminder(bool seedOnCmdline) {
    printf("\n  %s%sWhen you're done, wipe the seed from view:%s\n", B, RED, R);
    printf("      %sclear && printf '\\033c'%s        %s# clears the screen AND scrollback buffer%s\n", B, R, DIM, R);
    if (seedOnCmdline) {
        printf("      %shistory -d $((HISTCMD-1)) 2>/dev/null; history -c%s   %s# drop this seed from shell history%s\n", B, R, DIM, R);
        printf("  %sTip: next time run `xcoin-wallet new` (or restore, then paste when prompted) so the seed never lands in history.%s\n", DIM, R);
    }
    printf("  %sClose the Terminal window afterward to be safe. The seed also lives in %s%s — guard that file.%s\n",
           DIM, B, "~/.xcoin/wallet.seed", R);
}
static void usage() {
    banner();
    fprintf(stderr,
        "\nUsage:\n"
        "  xcoin-wallet new                 Create a new wallet (generates + saves your seed)\n"
        "  xcoin-wallet address [--index N] Show your receiving address (N defaults to 0)\n"
        "  xcoin-wallet restore <64-hex>    Save an existing seed as your wallet\n"
        "  xcoin-wallet show                Show wallet status + address\n"
        "\nThe address is the two-leaf witness v3 tree {ML-DSA-65, SLH-DSA-SHA2-128s fallback};\n"
        "the single-leaf (carried) form of the same key is shown too and stays spendable.\n"
        "\nOptions:\n"
        "  --file <path>   Wallet file (default: ~/.xcoin/wallet.seed)\n"
        "  --seed <hex>    Use this seed directly instead of the wallet file\n"
        "  --index <N>     Derive key index N (default 0)\n"
        "  --hrp <hrp>     Address prefix: xpa (mainnet, default) or txa (testnet A)\n"
        "\nThe seed is your ENTIRE backup. Write it on paper/metal, offline. Anyone with the\n"
        "seed controls the coins; nobody can spend them without it. Never share or upload it.\n");
}

// ── offline signer ─────────────────────────────────────────────────────────────
// Reads from stdin (nothing secret on argv):
//   line 1: seed hex
//   line 2: unsigned raw tx hex
//   lines 3+: one prevout per input — "<txid> <vout> <scriptPubKeyHex> <amountSats> <keyindex>"
// Writes the signed tx hex to stdout. The seed never leaves this process; there
// is no network access. Witness v3 inputs (OP_3 <program>) are matched against the
// key index's two-leaf tree {ML-DSA, SLH-DSA} and its carried single-leaf tree
// {ML-DSA}, and signed through the ML-DSA-65 leaf of whichever one the program is
// (the matching is dex-wallet-cli's cmd_sign). Legacy witness v2 inputs keep the
// first-chain BIP143 path.
struct PrevOut { uint8_t hash[32]; uint32_t vout; std::vector<uint8_t> spk; uint64_t amount; uint32_t keyindex; };

// Precomputed single-SHA256 hashes over the whole transaction, exactly the
// BIP-341 set (prevouts / spent amounts / spent scriptPubKeys / sequences /
// outputs). Spent-output data must be in INPUT ORDER.
struct V3TxHashes { uint8_t prevouts[32], amounts[32], scripts[32], sequences[32], outputs[32]; };
static void v3_precompute(const Tx& tx, const std::vector<const PrevOut*>& byin, V3TxHashes& h) {
    std::vector<uint8_t> t;
    for (auto& in : tx.vin) { t.insert(t.end(), in.hash, in.hash + 32); put_u32le(t, in.vout); }
    ssha256(t, h.prevouts); t.clear();
    for (auto* p : byin) put_u64le(t, p->amount);
    ssha256(t, h.amounts); t.clear();
    for (auto* p : byin) { put_compact(t, p->spk.size()); t.insert(t.end(), p->spk.begin(), p->spk.end()); }
    ssha256(t, h.scripts); t.clear();
    for (auto& in : tx.vin) put_u32le(t, in.sequence);
    ssha256(t, h.sequences); t.clear();
    for (auto& o : tx.vout) { put_u64le(t, o.value); put_compact(t, o.spk.size()); t.insert(t.end(), o.spk.begin(), o.spk.end()); }
    ssha256(t, h.outputs);
}
// The v3 sighash, SIGHASH_DEFAULT (0x00) only — the node wallet's own choice.
// Step 1: TaggedHash("TapSighash", BIP-341 fields with ext_flag=1 (spend_type
// 0x02, no annex), key_version 0x02 (ML-DSA), codeseparator 0xFFFFFFFF).
// Step 2: TaggedHash("XCoinSighash/v3", step-1 message). The result IS the
// message handed to ML-DSA-65 (FIPS 204 pure mode, empty context) — it is
// never hashed again.
static void v3_sighash(const Tx& tx, size_t nIn, const V3TxHashes& h, const uint8_t leafhash[32], uint8_t out[32]) {
    std::vector<uint8_t> m;
    m.push_back(0x00);                       // epoch
    m.push_back(0x00);                       // hash_type = SIGHASH_DEFAULT
    put_u32le(m, tx.version);
    put_u32le(m, tx.locktime);
    m.insert(m.end(), h.prevouts,  h.prevouts  + 32);
    m.insert(m.end(), h.amounts,   h.amounts   + 32);
    m.insert(m.end(), h.scripts,   h.scripts   + 32);
    m.insert(m.end(), h.sequences, h.sequences + 32);
    m.insert(m.end(), h.outputs,   h.outputs   + 32);
    m.push_back(0x02);                       // spend_type = ext_flag(1)<<1 | annex(0)
    put_u32le(m, (uint32_t)nIn);
    m.insert(m.end(), leafhash, leafhash + 32);
    m.push_back(0x02);                       // key_version: ML-DSA
    put_u32le(m, 0xFFFFFFFF);                // no OP_CODESEPARATOR executed
    uint8_t step1[32];
    tagged_hash(TAG_SIGHASH_BIP341, m, step1);
    tagged_hash(TAG_SIGHASH_V3, std::vector<uint8_t>(step1, step1 + 32), out);
}

static int cmd_sign() {
    std::string seedhex, txhex, line;
    if (!std::getline(std::cin, seedhex) || !std::getline(std::cin, txhex)) {
        fprintf(stderr, "sign: expected seed and tx on stdin\n"); return 1;
    }
    auto trim = [](std::string& s){ while(!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' ')) s.pop_back(); };
    trim(seedhex); trim(txhex);

    std::vector<uint8_t> seed, raw;
    if (!from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) { fprintf(stderr,"sign: bad seed\n"); return 1; }
    if (!seedhex.empty()) memset(&seedhex[0], 0, seedhex.size());
    if (!from_hex(txhex, raw)) { wipe(seed); fprintf(stderr,"sign: bad tx hex\n"); return 1; }

    std::vector<PrevOut> prevs;
    while (std::getline(std::cin, line)) {
        trim(line); if (line.empty()) continue;
        char txid[256]={0}, spk[8192]={0}; unsigned long vout=0, kidx=0; unsigned long long amt=0;
        if (sscanf(line.c_str(), "%255s %lu %8191s %llu %lu", txid, &vout, spk, &amt, &kidx) != 5) {
            wipe(seed); fprintf(stderr,"sign: bad prevout line\n"); return 1;
        }
        PrevOut p; std::vector<uint8_t> th, sp;
        if (!from_hex(txid, th) || th.size()!=32 || !from_hex(spk, sp)) { wipe(seed); fprintf(stderr,"sign: bad prevout hex\n"); return 1; }
        for (int i=0;i<32;i++) p.hash[i]=th[31-i];   // display txid -> internal byte order
        p.vout=(uint32_t)vout; p.spk=sp; p.amount=(uint64_t)amt; p.keyindex=(uint32_t)kidx;
        prevs.push_back(std::move(p));
    }

    Tx tx;
    if (!parse_tx(raw, tx)) { wipe(seed); fprintf(stderr,"sign: could not parse tx\n"); return 1; }

    // Align prevouts to inputs first: the v3 sighash commits to every spent
    // output (amounts + scriptPubKeys) in input order, not just the one signed.
    std::vector<const PrevOut*> byin(tx.vin.size(), nullptr);
    for (size_t i=0;i<tx.vin.size();i++) {
        for (auto& p : prevs) if (p.vout==tx.vin[i].vout && memcmp(p.hash,tx.vin[i].hash,32)==0) { byin[i]=&p; break; }
        if (!byin[i]) { wipe(seed); fprintf(stderr,"sign: no prevout for input %zu\n", i); return 1; }
    }
    V3TxHashes v3h; bool v3ready=false;

    std::vector<std::vector<std::vector<uint8_t>>> witness(tx.vin.size());
    for (size_t i=0;i<tx.vin.size();i++) {
        const PrevOut* pv=byin[i];
        KeyMaterial km;                          // its destructor wipes the ML-DSA secret key on every path
        if (!derive_key_material(seed, pv->keyindex, km, true)) { wipe(seed); fprintf(stderr,"sign: key derivation failed\n"); return 1; }

        if (pv->spk.size()==34 && pv->spk[0]==0x53 && pv->spk[1]==0x20) {
            // witness v3 (OP_3 PUSH32): the ML-DSA leaf of the two-leaf tree, or of the
            // carried single-leaf tree. The leaf, its hash and so the sighash are the
            // same in both; only the control block differs (65 vs 33 bytes).
            const bytes program(pv->spk.begin()+2, pv->spk.end());
            const KeyTrees t = build_trees(km.pq_hash, km.slh_pk);
            const bool two_leaf = program == t.root2;
            const bool single_leaf = program == t.root1;
            if (!two_leaf && !single_leaf) { wipe(seed); fprintf(stderr,"sign: key at index %u does not control input %zu (neither its two-leaf nor its carried tree)\n", pv->keyindex, i); return 1; }
            if (!v3ready) { v3_precompute(tx, byin, v3h); v3ready=true; }
            uint8_t sighash[32]; v3_sighash(tx, i, v3h, t.leaf_pq.data(), sighash);
            std::vector<uint8_t> sig(PQ_SIG); size_t siglen=0;
            int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(),&siglen, sighash,32, km.pq_sk.data());
            wipe(km.pq_sk);
            if (ret!=0 || siglen!=PQ_SIG) { wipe(seed); fprintf(stderr,"sign: ML-DSA signing failed on input %zu\n", i); return 1; }
            if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig.data(),sig.size(), sighash,32, km.pq_pk.data())!=0) {
                wipe(seed); fprintf(stderr,"sign: ML-DSA self-check failed on input %zu\n", i); return 1;
            }
            // SIGHASH_DEFAULT: the bare 3,309-byte signature. An explicit 0x00
            // hashtype byte is consensus-invalid (one encoding per sighash).
            witness[i] = { km.pq_pk, sig, t.leaf_pq_script, two_leaf ? t.control_pq2 : t.control_pq1 };
        } else if (pv->spk.size()==34 && pv->spk[0]==0x52 && pv->spk[1]==0x20) {
            // legacy witness v2 (OP_2 PUSH32): BIP143-style, kept for sweeping
            // pre-regenesis coins on private chains. The live chains reject v2.
            if (memcmp(km.pq_hash.data(), pv->spk.data()+2, 32)!=0) { wipe(seed); fprintf(stderr,"sign: key at index %u does not control input %zu\n", pv->keyindex, i); return 1; }
            uint8_t sighash[32];
            bip143_sighash(tx, i, pv->spk, pv->amount, sighash);   // scriptCode == scriptPubKey here
            std::vector<uint8_t> sig(PQ_SIG); size_t siglen=0;
            int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(),&siglen, sighash,32, km.pq_sk.data());
            wipe(km.pq_sk);
            if (ret!=0) { wipe(seed); fprintf(stderr,"sign: ML-DSA signing failed on input %zu\n", i); return 1; }
            sig.resize(siglen); sig.push_back(0x01);               // trailing SIGHASH_ALL byte
            witness[i].push_back(sig);
            witness[i].push_back(km.pq_pk);
        } else {
            wipe(seed);
            fprintf(stderr,"sign: input %zu is neither witness-v3 nor witness-v2 PQ\n", i); return 1;
        }
    }

    memset(seed.data(), 0, seed.size());   // seed no longer needed once every input is signed

    // serialize signed tx (segwit format)
    std::vector<uint8_t> out;
    put_u32le(out, tx.version);
    out.push_back(0x00); out.push_back(0x01);                  // marker, flag
    put_compact(out, tx.vin.size());
    for (auto& in : tx.vin) { out.insert(out.end(), in.hash, in.hash+32); put_u32le(out, in.vout); put_compact(out, in.scriptSig.size()); out.insert(out.end(), in.scriptSig.begin(), in.scriptSig.end()); put_u32le(out, in.sequence); }
    put_compact(out, tx.vout.size());
    for (auto& o : tx.vout) { put_u64le(out, o.value); put_compact(out, o.spk.size()); out.insert(out.end(), o.spk.begin(), o.spk.end()); }
    for (auto& w : witness) { put_compact(out, w.size()); for (auto& item : w) { put_compact(out, item.size()); out.insert(out.end(), item.begin(), item.end()); } }
    put_u32le(out, tx.locktime);

    printf("%s\n", to_hex(out.data(), out.size()).c_str());
    return 0;
}

// Debug: print the BIP143 sighash. stdin: txhex, "<txid> <vout> <spkHex> <amountSats>", inputIndex.
// ── address derivation for the Python CLI ──────────────────────────────────────
// Reads the seed hex from stdin line 1 (never argv, never the node); --index N on
// argv. Prints one JSON object: the two-leaf address/scriptPubKey/program, the
// carried single-leaf carried_address/carried_scriptPubKey/carried_program, and
// "identity" (the xid1… forum handle of the same key), so wallet_cli.py can
// derive addresses without the seed leaving this host.
static int cmd_address_json(int argc, char** argv) {
    uint32_t index = 0;
    for (int i = 2; i + 1 < argc; i++)
        if (std::string(argv[i]) == "--index") index = (uint32_t)strtoul(argv[++i], nullptr, 10);
    std::string seedhex;
    if (!std::getline(std::cin, seedhex)) { fprintf(stderr, "_address: expected seed on stdin\n"); return 1; }
    while (!seedhex.empty() && (seedhex.back() == '\n' || seedhex.back() == '\r' || seedhex.back() == ' '))
        seedhex.pop_back();
    std::vector<uint8_t> seed;
    if (seedhex.size() < 64 || seedhex.size() > 128 || !from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) {
        fprintf(stderr, "_address: seed must be 32-64 bytes of hex (64-128 chars)\n"); return 1;
    }
    KeyMaterial km;
    const bool ok = derive_key_material(seed, index, km, false);
    wipe(seed);
    if (!ok) { fprintf(stderr, "_address: key derivation failed\n"); return 1; }
    const KeyTrees t = build_trees(km.pq_hash, km.slh_pk);
    // "address"/"scriptPubKey"/"program" are the two-leaf tree; carried_* the single-leaf one.
    printf("{\"address\":\"%s\",\"identity\":\"%s\",\"scriptPubKey\":\"%s\",\"program\":\"%s\",\"pubkey_sha256\":\"%s\","
           "\"carried_address\":\"%s\",\"carried_scriptPubKey\":\"%s\",\"carried_program\":\"%s\",\"index\":%u}\n",
           v3_address(g_hrp, t.root2).c_str(), identity_from_hash(km.pq_hash).c_str(), v3_spk_hex(t.root2).c_str(),
           to_hex(t.root2.data(), 32).c_str(), to_hex(km.pq_hash.data(), 32).c_str(),
           v3_address(g_hrp, t.root1).c_str(), v3_spk_hex(t.root1).c_str(), to_hex(t.root1.data(), 32).c_str(), index);
    return 0;
}

static int cmd_sighash() {
    std::string txhex, prevline, idxline;
    if (!std::getline(std::cin,txhex)||!std::getline(std::cin,prevline)||!std::getline(std::cin,idxline)) return 1;
    std::vector<uint8_t> raw; if(!from_hex(txhex,raw)) return 1;
    char txid[256]={0}, spk[8192]={0}; unsigned long vout=0; unsigned long long amt=0;
    if (sscanf(prevline.c_str(),"%255s %lu %8191s %llu",txid,&vout,spk,&amt)!=4) return 1;
    size_t nIn = strtoul(idxline.c_str(),nullptr,10);
    std::vector<uint8_t> sp; if(!from_hex(spk,sp)) return 1;
    Tx tx; if(!parse_tx(raw,tx)) return 1;
    uint8_t sh[32]; bip143_sighash(tx,nIn,sp,(uint64_t)amt,sh);
    printf("%s\n", to_hex(sh,32).c_str());
    return 0;
}
// Sign an arbitrary message (a forum login challenge) with the key at --index N.
// stdin: line 1 = seed hex, line 2 = message hex (never argv). FIPS 204 pure
// ML-DSA-65 with an empty context, the same call the transaction signer uses,
// so any FIPS 204 verifier (the forum's) accepts it. Prints one JSON line:
// {"address","identity","pubkey","sig","index"} ("address" is the two-leaf form).
// The seed and secret key are wiped.
static int cmd_signmsg(int argc, char** argv) {
    uint32_t index = 0;
    for (int i = 2; i + 1 < argc; i++)
        if (std::string(argv[i]) == "--index") index = (uint32_t)strtoul(argv[++i], nullptr, 10);
    std::string seedhex, msghex;
    if (!std::getline(std::cin, seedhex) || !std::getline(std::cin, msghex)) { fprintf(stderr, "_signmsg: expected seed hex and message hex on stdin\n"); return 1; }
    auto trim = [](std::string& t){ while(!t.empty() && (t.back()=='\n'||t.back()=='\r'||t.back()==' ')) t.pop_back(); };
    trim(seedhex); trim(msghex);
    std::vector<uint8_t> seed, msg;
    if (seedhex.size() < 64 || seedhex.size() > 128 || !from_hex(seedhex, seed) || seed.size() < 32 || seed.size() > 64) {
        fprintf(stderr, "_signmsg: seed must be 32-64 bytes of hex (64-128 chars)\n"); return 1;
    }
    if (!from_hex(msghex, msg) || msg.empty()) { memset(seed.data(), 0, seed.size()); fprintf(stderr, "_signmsg: bad message hex\n"); return 1; }
    // A v3 spend sighash is exactly 32 bytes (the SLH leaf's message is 34). Refuse
    // anything short enough to be one, so a sign-in challenge can never double as a
    // spend signature for this key. Real sign-in messages are long text.
    if (msg.size() < 65) {
        memset(seed.data(), 0, seed.size());
        fprintf(stderr, "_signmsg: refusing to sign a message shorter than 65 bytes (a spend sighash is 32)\n");
        return 1;
    }
    KeyMaterial km;                          // its destructor wipes the ML-DSA secret key on every path
    const bool ok = derive_key_material(seed, index, km, true);
    wipe(seed);
    if (!ok) { fprintf(stderr, "_signmsg: key derivation failed\n"); return 1; }
    std::vector<uint8_t> sig(PQ_SIG);
    size_t siglen = 0;
    const int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(), &siglen, msg.data(), msg.size(), km.pq_sk.data());
    wipe(km.pq_sk);
    if (ret != 0 || siglen == 0 || siglen > sig.size()) { fprintf(stderr, "_signmsg: signing failed\n"); return 1; }
    sig.resize(siglen);
    const KeyTrees t = build_trees(km.pq_hash, km.slh_pk);
    printf("{\"address\":\"%s\",\"identity\":\"%s\",\"pubkey\":\"%s\",\"sig\":\"%s\",\"index\":%u}\n",
           v3_address(g_hrp, t.root2).c_str(), identity_from_hash(km.pq_hash).c_str(),
           to_hex(km.pq_pk.data(), km.pq_pk.size()).c_str(), to_hex(sig.data(), sig.size()).c_str(), index);
    return 0;
}

// Debug: crypto_sign_verify. stdin: pubkeyHex, sighashHex(msg), sigHex. Prints OK/FAIL.
static int cmd_verify() {
    std::string pkh, mh, sh;
    if(!std::getline(std::cin,pkh)||!std::getline(std::cin,mh)||!std::getline(std::cin,sh)) return 1;
    std::vector<uint8_t> pk,m,sig; if(!from_hex(pkh,pk)||!from_hex(mh,m)||!from_hex(sh,sig)) return 1;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig.data(),sig.size(), m.data(),m.size(), pk.data());
    printf("%s\n", ret==0 ? "OK" : "FAIL");
    return ret==0?0:1;
}

// Replay the node's golden vectors (src/test/xcoin_v3_tests.cpp). Prints one
// line per vector; exits nonzero on any mismatch. Run by tests and build.sh.
static int cmd_v3vectors() {
    int fails = 0;
    auto check = [&](const char* name, const uint8_t got[32], const char* want) {
        std::string g = to_hex(got, 32);
        if (g != want) { printf("FAIL %s: %s != %s\n", name, g.c_str(), want); fails++; }
        else printf("ok   %s\n", name);
    };
    uint8_t nk[32]; ssha256((const uint8_t*)TAG_NOKEY, strlen(TAG_NOKEY), nk);
    check("nokey", nk, "54b62806c9e55d19448216fc3426a3a04466fbc59c18238795cbbc9003330a65");
    std::vector<uint8_t> s1{0x20}; for (uint8_t i = 1; i <= 32; i++) s1.push_back(i); s1.push_back(0xac);
    uint8_t l1[32]; v3_leaf_hash(0xc0, s1, l1);
    check("leaf-pq", l1, "50371c2936f8bfda05c69228affb83119c687ad8a477b1a18bd01c0a468902d6");
    uint8_t l2[32]; v3_leaf_hash(0xc0, std::vector<uint8_t>{}, l2);
    check("leaf-empty", l2, "e3bb8e8060cd8ae48c5e91228aa5c257cd5bb80ae1cf853f4dec66a042b1c2f9");
    uint8_t l3[32]; v3_leaf_hash(0xc2, std::vector<uint8_t>{0x51}, l3);
    check("leaf-slh", l3, "cb25e1b1ec8b174d327f1e6466c018383dd0e23860f6805cab1738dd65922adf");
    // The branch vectors run through branch_hash, the very function the address trees use.
    const bytes L1(l1, l1 + 32), L2(l2, l2 + 32), L3(l3, l3 + 32);
    const bytes b12 = branch_hash(L1, L2);
    check("branch12", b12.data(), "2339dd5ab68ae3ec676b327297e620ce7f2f7e7eb594be396a12ce600df76845");
    check("branch-sorted", branch_hash(L2, L1).data(), "2339dd5ab68ae3ec676b327297e620ce7f2f7e7eb594be396a12ce600df76845");
    check("branch123", branch_hash(b12, L3).data(), "44546098ecf80a10fbf7441c650152021a8f099a8eb816d80a04e0f01df60687");
    uint8_t z[32] = {0}, tg[32];
    tagged_hash(TAG_SIGHASH_V3, std::vector<uint8_t>(z, z + 32), tg);
    check("sighash-tag-zero", tg, "ca2115605609aa667201bcb32f4fb217d4a673fa026e8ba76adbf01dc4ed37cd");
    const bytes ctrl = control_block(XCOIN_LEAF_PQ, nullptr);
    if (ctrl.size() == 33 && ctrl[0] == 0xc0 && memcmp(ctrl.data() + 1, nk, 32) == 0) printf("ok   control-block\n");
    else { printf("FAIL control-block\n"); fails++; }
    const bytes ctrl2 = control_block(XCOIN_LEAF_PQ, &L3);
    if (ctrl2.size() == 65 && ctrl2[0] == 0xc0 && memcmp(ctrl2.data() + 1, nk, 32) == 0 && memcmp(ctrl2.data() + 33, l3, 32) == 0) printf("ok   control-block-two-leaf\n");
    else { printf("FAIL control-block-two-leaf\n"); fails++; }

    // Sighash regression lock: a fixed 2-in/2-out transaction, message bytes
    // per input. The construction these constants pin produced the spends the
    // chain accepted and mined on 2026-09-24 (88665c29…, f035c14d…, cd5b6f71…);
    // any drift in field order, hashing or endianness fails here first.
    {
        Tx tx; tx.version = 2; tx.locktime = 700;
        TxIn i0{}; memset(i0.hash, 0x11, 32); i0.vout = 0; i0.sequence = 0xfffffffd;
        TxIn i1{}; memset(i1.hash, 0x22, 32); i1.vout = 1; i1.sequence = 0xfffffffd;
        tx.vin = {i0, i1};
        TxOut o0; o0.value = 100000; o0.spk = {0x53, 0x20}; o0.spk.insert(o0.spk.end(), 32, 0xaa);
        TxOut o1; o1.value = 250000; o1.spk = {0x53, 0x20}; o1.spk.insert(o1.spk.end(), 32, 0xbb);
        tx.vout = {o0, o1};
        PrevOut p0{}; memcpy(p0.hash, i0.hash, 32); p0.vout = 0; p0.amount = 300000;
        p0.spk = {0x53, 0x20}; p0.spk.insert(p0.spk.end(), 32, 0xcc);
        PrevOut p1{}; memcpy(p1.hash, i1.hash, 32); p1.vout = 1; p1.amount = 60000;
        p1.spk = {0x53, 0x20}; p1.spk.insert(p1.spk.end(), 32, 0xdd);
        std::vector<const PrevOut*> byin{&p0, &p1};
        V3TxHashes h; v3_precompute(tx, byin, h);
        uint8_t lh0[32]; memset(lh0, 0xee, 32);
        uint8_t lh1[32]; memset(lh1, 0xff, 32);
        uint8_t sh0[32], sh1[32];
        v3_sighash(tx, 0, h, lh0, sh0);
        v3_sighash(tx, 1, h, lh1, sh1);
        if (getenv("V3VECTORS_GEN")) { printf("gen  sighash-in0 %s\n", to_hex(sh0, 32).c_str()); printf("gen  sighash-in1 %s\n", to_hex(sh1, 32).c_str()); }
        else {
            check("sighash-in0", sh0, "c12202292bdb20c61dc34f13381c1d589854ab0436ac34fb69ea1162d30fa187");
            check("sighash-in1", sh1, "966b91132bec61fe663d0636ce13b4cc56742c34e9c18e7ebfe0df5e034622dd");
        }
    }

    // Cross-implementation lock: for the test seed ab*32 the two-leaf program
    // (root2) and the carried single-leaf program (root1) must equal what
    // dex-wallet-cli's keytool derives (`derive --index N`, commit 4923eae). This
    // pins the whole chain: HD derivation, ML-DSA-65 keygen, the SLH-DSA seed and
    // keygen, leaf scripts, leaf/branch hashes and bech32m.
    {
        struct { uint32_t index; const char* root2; const char* root1; const char* addr2; const char* addr1; } want[] = {
            {0,   "5f26280ed5567edd3afffe4598d23c01d05ca2b059ce2f967109f5687919052b",
                  "6d6e53f204007591343ba36669c6dc89b25ec37d46eec738274f7bcbfc1c66c0",
                  "xpa1rtunzsrk42eld6whlleze353uq8g9eg4st88zl9n3p86ks7geq54sykmt2m",
                  "xpa1rd4h98usyqp6ezdpm5dnxn3ku3xe9asmagmhvwwp8faauhlquvmqqdzf205"},
            {101, "c788704eb15510157f202d8672381ea95367d821ebda4209ad342b5fb53715ca",
                  "66dd3b10f9a4f1e105b3691ae81cf3082af7cabd2e0d9f4c978d12e2cf360d8f",
                  "xpa1rc7y8qn4325gp2leq9kr8ywq749fk0kppa0dyyzddxs44ldfhzh9qkndd5r",
                  "xpa1rvmwnky8e5nc7zpdndydws88npq400j4a9cxe7nyh35fw9nekpk8snyc8zr"},
        };
        const bytes seed(32, 0xab);
        for (auto& v : want) {
            KeyMaterial km;
            const std::string n = std::to_string(v.index);
            if (!derive_key_material(seed, v.index, km, false)) { printf("FAIL dex-keys-%s: derivation failed\n", n.c_str()); fails++; continue; }
            const KeyTrees t = build_trees(km.pq_hash, km.slh_pk);
            check(("dex-two-leaf-" + n).c_str(), t.root2.data(), v.root2);
            check(("dex-carried-" + n).c_str(), t.root1.data(), v.root1);
            const std::string a2 = v3_address("xpa", t.root2), a1 = v3_address("xpa", t.root1);
            if (a2 == v.addr2 && a1 == v.addr1) printf("ok   dex-addresses-%s\n", n.c_str());
            else { printf("FAIL dex-addresses-%s: %s %s\n", n.c_str(), a2.c_str(), a1.c_str()); fails++; }
            if (t.control_pq2.size() == 65 && t.control_pq1.size() == 33 &&
                bytes(t.control_pq2.begin() + 33, t.control_pq2.end()) == t.leaf_slh) printf("ok   dex-controls-%s\n", n.c_str());
            else { printf("FAIL dex-controls-%s\n", n.c_str()); fails++; }
        }
    }
    return fails == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    bool hrp_flag = false;
    for (int i = 2; i < argc; i++)
        if (std::string(argv[i]) == "--hrp") {
            if (i + 1 >= argc) { fprintf(stderr, "error: --hrp requires a value (xpa or txa)\n"); return 1; }
            g_hrp = argv[++i]; hrp_flag = true;
        }
    // The env var is a fallback for flagless callers, never an override: an
    // explicit --hrp always wins (a stale export must not flip address forms).
    if (!hrp_flag)
        if (const char* e = getenv("XCOIN_HRP")) if (*e) g_hrp = e;
    if (g_hrp != "xpa" && g_hrp != "txa") { fprintf(stderr, "error: --hrp must be xpa (mainnet) or txa (testnet A)\n"); return 1; }
    if (std::string(argv[1]) == "sign") return cmd_sign();
    if (std::string(argv[1]) == "_v3vectors") return cmd_v3vectors();
    if (std::string(argv[1]) == "_sighash") return cmd_sighash();
    if (std::string(argv[1]) == "_verify") return cmd_verify();
    if (std::string(argv[1]) == "_address") return cmd_address_json(argc, argv);
    if (std::string(argv[1]) == "_signmsg") return cmd_signmsg(argc, argv);
    std::string cmd = argv[1];
    std::string file = default_wallet_path(), seedOpt, arg;
    uint32_t index = 0;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--file" && i + 1 < argc) file = argv[++i];
        else if (a == "--seed" && i + 1 < argc) seedOpt = argv[++i];
        else if (a == "--index" && i + 1 < argc) index = (uint32_t)strtoul(argv[++i], nullptr, 10);
        else if (a == "--hrp" && i + 1 < argc) ++i;   // consumed before dispatch
        else if (a.rfind("--", 0) != 0) arg = a;
    }

    auto derive_and_print = [&](const std::vector<uint8_t>& seed) -> int {
        KeyMaterial km;
        if (!derive_key_material(seed, index, km, false)) { fprintf(stderr, "%serror:%s key derivation failed\n", RED, R); return 1; }
        const KeyTrees t = build_trees(km.pq_hash, km.slh_pk);
        const std::string addr = v3_address(g_hrp, t.root2);
        print_address_block(km, t, index);
        printf("  %smining:%s use %s%s.yourRigName%s as the pool username to show a worker\n",
               DIM, R, B, addr.c_str(), R);
        printf("  %s        name on the leaderboard (Discord + superknet.com)%s\n", DIM, R);
        return 0;
    };

    if (cmd == "new") {
        banner();
        // NEVER silently overwrite an existing wallet: the previous seed would be
        // destroyed and any coins on its addresses lost forever.
        std::string existing;
        if (read_seed_file(file, existing)) {
            fprintf(stderr, "%srefusing to overwrite%s %s — a wallet already exists there.\n",
                    RED, R, file.c_str());
            fprintf(stderr, "  Its funds would be LOST. Use `xcoin-wallet show` to see it,\n");
            fprintf(stderr, "  or create a second wallet with:  xcoin-wallet new --file <other-path>\n");
            return 1;
        }
        uint8_t s[32]; arc4random_buf(s, 32);
        std::string seedhex = to_hex(s, 32);
        std::vector<uint8_t> seed(s, s + 32); memset(s, 0, sizeof(s));
        if (!write_seed_file(file, seedhex)) { fprintf(stderr, "%serror:%s could not write %s\n", RED, R, file.c_str()); return 1; }
        printf("\n  %s%s⚠  BACK UP YOUR SEED — this is the ONLY way to recover your coins:%s\n", B, YEL, R);
        printf("  %s%s%s%s\n", B, YEL, seedhex.c_str(), R);
        printf("  %sSaved (encrypted at rest by your Mac's FileVault) to: %s%s\n", DIM, file.c_str(), R);
        printf("  %sWrite the 64-hex seed on paper/metal and store it offline. Do not screenshot or upload it.%s\n", DIM, R);
        int rc = derive_and_print(seed);
        wipe_reminder(false);
        return rc;
    }
    if (cmd == "restore") {
        banner();
        std::string existing;
        if (read_seed_file(file, existing)) {
            fprintf(stderr, "%srefusing to overwrite%s %s — a wallet already exists there.\n",
                    RED, R, file.c_str());
            fprintf(stderr, "  Restore to a different file with:  xcoin-wallet restore <seed> --file <other-path>\n");
            return 1;
        }
        std::string sh = !seedOpt.empty() ? seedOpt : arg;
        std::vector<uint8_t> seed;
        if (sh.size() < 64 || sh.size() > 128 || !from_hex(sh, seed) || seed.size() < 32 || seed.size() > 64) {
            fprintf(stderr, "%serror:%s seed must be 32–64 bytes of hex (64–128 chars)\n", RED, R); return 1;
        }
        if (!write_seed_file(file, sh)) { fprintf(stderr, "%serror:%s could not write %s\n", RED, R, file.c_str()); return 1; }
        printf("  %sseed saved to %s%s\n", DIM, file.c_str(), R);
        int rc = derive_and_print(seed);
        wipe_reminder(true);   // seed was on the command line → also purge shell history
        return rc;
    }
    if (cmd == "address" || cmd == "show") {
        std::string sh = seedOpt;
        if (sh.empty() && !read_seed_file(file, sh)) {
            fprintf(stderr, "%sno wallet found%s at %s — run `xcoin-wallet new` first.\n", RED, R, file.c_str());
            return 1;
        }
        std::vector<uint8_t> seed;
        if (!from_hex(sh, seed) || seed.size() < 32 || seed.size() > 64) {
            fprintf(stderr, "%serror:%s wallet seed is not valid hex\n", RED, R); return 1;
        }
        if (cmd == "show") { banner(); printf("  %swallet file:%s %s\n", DIM, R, file.c_str()); }
        return derive_and_print(seed);
    }
    usage();
    return 1;
}
