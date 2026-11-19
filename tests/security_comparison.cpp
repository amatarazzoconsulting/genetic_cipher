// Diagnostic experiments, not a cryptographic security certification.
#include "../genetic_cipher.hpp"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <iostream>
#include <iomanip>
#include <stdexcept>
using namespace genetic_cipher;
using Bytes = std::vector<uint8_t>;
void require(bool ok) { if (!ok) throw std::runtime_error("comparison check failed"); }
container_t container(const Bytes& b) {
    container_t c(4096, BitMode::BYTE); c.append_bytes(b.data(), b.size()); return c;
}
template<class C> Bytes genetic(const Bytes& b, bool decrypt = false, bool wrong = false) {
    C c;
    c.set_password(std::string(wrong ? "wrong-password" : "test-passphrase"));
    c.set_electronic_password(std::string("test-device-secret"));
    c.settings().minimum_encrypted_size = 0;
    return (decrypt ? c.decrypt(container(b)) : c.encrypt(container(b))).to_bytes();
}
size_t distance(const Bytes& a, const Bytes& b) {
    require(a.size() == b.size()); size_t d = 0;
    for (size_t i = 0; i < a.size(); ++i) d += std::popcount(unsigned(a[i] ^ b[i]));
    return d;
}
struct Sealed { Bytes data; std::array<uint8_t,16> tag{}; };
Sealed seal(const EVP_CIPHER* cipher, const Bytes& p, unsigned nonce_id) {
    std::array<uint8_t,32> key{}; // Synthetic test key only.
    std::array<uint8_t,12> nonce{}; nonce.back() = nonce_id;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(bool(ctx));
    require(EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), nonce.data()) == 1);
    Sealed s; s.data.resize(p.size()+16); int n = 0, tail = 0;
    require(EVP_EncryptUpdate(ctx.get(), s.data.data(), &n, p.data(), int(p.size())) == 1);
    require(EVP_EncryptFinal_ex(ctx.get(), s.data.data()+n, &tail) == 1);
    s.data.resize(n+tail);
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, s.tag.data()) == 1);
    return s;
}
bool open(const EVP_CIPHER* cipher, Sealed s, Bytes& p, bool wrong = false) {
    std::array<uint8_t,32> key{}; if (wrong) key[0] = 1;
    std::array<uint8_t,12> nonce{}; nonce.back() = 1;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(bool(ctx));
    require(EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), nonce.data()) == 1);
    p.resize(s.data.size()+16); int n = 0, tail = 0;
    require(EVP_DecryptUpdate(ctx.get(), p.data(), &n, s.data.data(), int(s.data.size())) == 1);
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, s.tag.data()) == 1);
    bool ok = EVP_DecryptFinal_ex(ctx.get(), p.data()+n, &tail) == 1;
    if (ok) p.resize(n+tail); else p.clear(); return ok;
}
template<class C> void profile(const char* name, const Bytes& p) {
    const auto start = std::chrono::steady_clock::now();
    auto a = genetic<C>(p);
    double ms = std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
    require(genetic<C>(a,true) == p);
    require(a == genetic<C>(p));
    auto modified = a; modified[0] ^= 1;
    require(genetic<C>(modified,true) != p); // accepted silently
    require(genetic<C>(a,true,true) != p);
    double changed = 0;
    for (size_t i = 0; i < 16; ++i) {
        auto q = p; q[i] ^= uint8_t(1u << (i % 8));
        changed += distance(a, genetic<C>(q));
    }
    std::cout << name << ": plaintext bit change=" << changed/16/(p.size()*8)*100
              << "%, deterministic=yes, tamper/wrong-key rejection=no, encryption=" << ms << " ms\n";
}
int main() {
    std::cout << OpenSSL_version(OPENSSL_VERSION) << "\n" << std::fixed << std::setprecision(3);
    Bytes p(4096); for (size_t i=0; i<p.size(); ++i) p[i]=uint8_t(i);
    profile<GeneticCipher<BitwiseXor>>("Genetic XOR only",p);
    profile<GeneticCipher<SquareTransform,CircleTransform,Scatter,Diffuse,BitwiseXor>>("Genetic README pipeline",p);
    // Demonstrate known-plaintext recovery from a supported XOR-only pipeline.
    auto a=genetic<GeneticCipher<BitwiseXor>>(p);
    Bytes secret(p.size(),0xA5), recovered(secret.size());
    auto b=genetic<GeneticCipher<BitwiseXor>>(secret);
    for(size_t i=0;i<p.size();++i) recovered[i]=a[i]^p[i]^b[i];
    require(recovered==secret);
    std::cout << "XOR-only known-plaintext attack: recovered all " << recovered.size() << " bytes\n";
    for (auto cipher : {EVP_aes_256_gcm(), EVP_chacha20_poly1305()}) {
        const auto start=std::chrono::steady_clock::now(); auto s=seal(cipher,p,1);
        double ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
        Bytes back; require(open(cipher,s,back) && back==p);
        require(s.data != seal(cipher,p,2).data);
        require(!open(cipher,s,back,true));
        auto bad=s; bad.data[0]^=1; require(!open(cipher,bad,back));
        bad=s; bad.tag[0]^=1; require(!open(cipher,bad,back));
        double changed=0;
        for(size_t i=0;i<16;++i) { auto q=p; q[i]^=uint8_t(1u<<(i%8)); changed+=distance(s.data,seal(cipher,q,1).data); }
        // Fixed nonce above is ONLY a controlled differential experiment, not safe usage.
        std::cout << EVP_CIPHER_get0_name(cipher) << ": plaintext bit change=" << changed/16/(p.size()*8)*100
                  << "%, distinct-nonce ciphertexts differ=yes, tamper/wrong-key rejection=yes, encryption=" << ms << " ms\n";
    }
}
