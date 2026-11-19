#include "../genetic_cipher.hpp"
#include <iostream>
#include <limits>
using namespace genetic_cipher;
size_t checks = 0;
void check(bool ok) { ++checks; if (!ok) throw std::runtime_error("shape/stack check " + std::to_string(checks)); }
template<class C> void configure(C& c, DistributionParams params = {}) {
    c.set_password(std::string("shape-test-passphrase"));
    c.set_electronic_password(std::string("shape-device-key"));
    c.settings().minimum_encrypted_size = 0;
    c.settings().shape_distribution = params;
}
container_t input(size_t n, BitMode mode = BitMode::WORD64) {
    container_t c(4096, mode);
    for (size_t i = 0; i < n; ++i) c.append_element(i); // many storage nodes
    return c;
}
template<class Shape> void shapes() {
    for (auto mode : {BitMode::BIT_1, BitMode::BIT_2, BitMode::BIT_3, BitMode::NIBBLE,
         BitMode::BIT_5, BitMode::BIT_6, BitMode::BYTE, BitMode::WORD16, BitMode::WORD32, BitMode::WORD64}) {
        for (size_t n : {size_t(1), size_t(7), size_t(64), size_t(257)}) {
            auto p = input(n, mode);
            GeneticCipher<Shape> a,b; configure(a); configure(b);
            auto enc = a.encrypt(p);
            auto dec = b.decrypt(enc);
            check(dec.element_count() == p.element_count());
            for (size_t i=0; i<n; ++i) check(dec.get_element(i) == p.get_element(i));
            // Test the element multiset, including packed widths.
            std::vector<uint64_t> values, original;
            for(size_t i=0;i<n;++i) { values.push_back(enc.get_element(i)); original.push_back(p.get_element(i)); }
            std::sort(values.begin(),values.end()); std::sort(original.begin(),original.end()); check(values==original);
        }
    }
}
int main() {
    shapes<TriangleTransform>(); shapes<PentagonTransform>(); shapes<HexagonTransform>();
    shapes<OctagonTransform>(); shapes<RegularPolygonTransform<7>>();
    auto p = input(1025);
    using C = GeneticCipher<PolygonTransform>;
    std::vector<uint8_t> previous;
    for (size_t depth : {size_t(0),size_t(1),size_t(3), std::numeric_limits<size_t>::max()}) {
        DistributionParams params; params.recursion_depth=depth; params.min_subdivision_size=2; params.max_subdivision_size=64;
        C a,b; configure(a,params); configure(b,params);
        auto enc=a.encrypt(p); check(enc.to_bytes()!=p.to_bytes());
        check(enc.get_element(1024)==1024); // incomplete grid tail unchanged
        check(b.decrypt(enc).to_bytes()==p.to_bytes());
        check(a.encrypt(p).to_bytes()==enc.to_bytes());
        if(!previous.empty()) check(previous!=enc.to_bytes());
        previous=enc.to_bytes();
    }
    for(double coverage : {0., 40., 100.}) for(double subdivision : {0., 50., 100.}) {
        DistributionParams params; params.coverage_percentage=coverage; params.subdivision_percentage=subdivision;
        C a,b; configure(a,params); configure(b,params);
        auto enc=a.encrypt(p); check(b.decrypt(enc).to_bytes()==p.to_bytes());
        if(coverage==0) check(enc.to_bytes()==p.to_bytes());
    }
    DistributionParams flat; flat.recursive_subdivisions=false;
    DistributionParams zero; zero.recursion_depth=0;
    C a,b; configure(a,flat); configure(b,zero); check(a.encrypt(p).to_bytes()==b.encrypt(p).to_bytes());
    for(int invalid=0;invalid<5;++invalid) {
        DistributionParams params;
        if(invalid==0) params.coverage_percentage=101;
        if(invalid==1) params.subdivision_percentage=-1;
        if(invalid==2) params.coverage_percentage=std::numeric_limits<double>::quiet_NaN();
        if(invalid==3) params.min_subdivision_size=0;
        if(invalid==4) params.max_subdivision_size=1;
        C bad; configure(bad,params);
        try { bad.encrypt(p); check(false); } catch(const std::invalid_argument&) { check(true); }
    }
    using Nested = GeneticCipher<PushMode, PolygonTransform, PushMode, TriangleTransform,
        SwitchMode, ModeCycle, Diffuse, ModeFeedback, PopMode, BitwiseXor, PopMode>;
    Nested writer,reader; configure(writer); configure(reader);
    for(int repeat=0;repeat<3;++repeat) {
        auto enc=writer.encrypt(p); check(reader.decrypt(enc).to_bytes()==p.to_bytes());
        Nested fresh; configure(fresh); check(fresh.decrypt(enc).to_bytes()==p.to_bytes());
    }
    // Existing stack tags do not change the data width. No-op payload verifies
    // this contract without comparing operations at different PRNG positions.
    GeneticCipher<PushMode,PushMode,SwitchMode,ModeCycle,ModeFeedback,PopMode,PopMode> stack;
    configure(stack); auto unchanged=stack.encrypt(p); check(unchanged.to_bytes()==p.to_bytes());
    check(stack.decrypt(unchanged).to_bytes()==p.to_bytes());
    GeneticCipher<PopMode,PopMode,PushMode,PopMode> underflow;
    configure(underflow); check(underflow.decrypt(underflow.encrypt(p)).to_bytes()==p.to_bytes());
    std::cout << checks << " shape and nested stack checks passed\n";
}
