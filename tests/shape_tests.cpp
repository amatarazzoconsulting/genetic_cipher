#include "../genetic_cipher.hpp"
#include <iostream>
#include <limits>
#include <set>
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
container_t packed_bytes(const std::vector<uint8_t>& bytes, BitMode mode) {
    const size_t width = bit_mode_to_size(mode);
    std::vector<uint64_t> values;
    uint64_t value = 0;
    size_t used = 0;
    for (uint8_t byte : bytes) {
        for (int bit = 7; bit >= 0; --bit) {
            value = (value << 1) | ((byte >> bit) & 1u);
            if (++used == width) {
                values.push_back(value);
                value = 0;
                used = 0;
            }
        }
    }
    if (used) values.push_back(value << (width - used));
    container_t result(4096, mode);
    result.append_elements(values.data(), values.size());
    return result;
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
    Grid2D line_grid(100);
    const auto diagonal = line_grid.plot_line(0, 0, 9, 6);
    check(diagonal.size() >= 10 && diagonal.front() == 0 && diagonal.back() == 69);
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

    GeneticCipher<PushMode,PushMode,SwitchMode,ModeCycle,ModeFeedback,PopMode,PopMode> stack;
    configure(stack); auto transformed=stack.encrypt(p);
    check(transformed.to_bytes()!=p.to_bytes());
    check(stack.decrypt(transformed).to_bytes()==p.to_bytes());
    GeneticCipher<PopMode,PopMode,PushMode,PopMode> underflow;
    configure(underflow); check(underflow.decrypt(underflow.encrypt(p)).to_bytes()==p.to_bytes());

    using WrappedShapes = GeneticCipher<PushMode, SquareTransform, Scatter, PopMode,
        PushMode, CircleTransform, Shuffle, PopMode, PushMode, TriangleTransform,
        Diffuse, PopMode>;
    WrappedShapes shape_writer, shape_reader;
    configure(shape_writer); configure(shape_reader);
    const auto wrapped = shape_writer.encrypt(p);
    check(wrapped.to_bytes() != p.to_bytes());
    check(shape_reader.decrypt(wrapped).to_bytes() == p.to_bytes());

    const auto geometry_source = input(1024, BitMode::BYTE);
    GeneticCipher<TriangleTransform> triangle_writer, triangle_reader;
    configure(triangle_writer); configure(triangle_reader);
    const auto triangle_cipher = triangle_writer.encrypt(geometry_source);
    check(triangle_cipher.to_bytes() != geometry_source.to_bytes());
    check(triangle_reader.decrypt(triangle_cipher).to_bytes() == geometry_source.to_bytes());

    const auto plain_bytes = input(64, BitMode::BYTE).to_bytes();
    std::vector<std::vector<uint8_t>> width_outputs;
    for (auto mode : {BitMode::BIT_1, BitMode::BIT_2, BitMode::BIT_3, BitMode::NIBBLE,
                      BitMode::BIT_5, BitMode::BIT_6, BitMode::BYTE, BitMode::WORD16,
                      BitMode::WORD32, BitMode::WORD64}) {
        auto source = packed_bytes(plain_bytes, mode);
        GeneticCipher<TransformChaCha, SquareTransform> enc, dec;
        configure(enc); configure(dec);
        const auto cipher = enc.encrypt(source);
        check(dec.decrypt(cipher).to_elements() == source.to_elements());
        width_outputs.push_back(cipher.to_bytes());
    }
    check(std::set<std::vector<uint8_t>>(width_outputs.begin(), width_outputs.end()).size() == 10);

    for (auto mode : {BitMode::BYTE, BitMode::WORD16, BitMode::WORD32, BitMode::WORD64}) {
        const auto source = input(1024, mode);
        GeneticCipher<CircleTransform> enc, dec;
        configure(enc); configure(dec);
        const auto cipher = enc.encrypt(source);
        check(cipher.to_bytes() != source.to_bytes());
        check(dec.decrypt(cipher).to_bytes() == source.to_bytes());
    }
    std::cout << checks << " shape and nested stack checks passed\n";
}
