#include "../genetic_cipher.hpp"
#include <iostream>
#include <random>
using namespace genetic_cipher;
int failures = 0;
size_t checks = 0;
void check(bool ok, const std::string& label) {
    ++checks;
    if (!ok) { ++failures; std::cerr << "FAIL " << label << '\n'; }
}
template<class C> void configure(C& c, size_t minimum = 0) {
    c.set_password(std::string("test-passphrase"));
    c.set_electronic_password(std::string("test-device-secret"));
    c.settings().minimum_encrypted_size = minimum;
}
template<class Op> void roundtrips(const char* name) {
    std::mt19937 rng(42);
    for (auto mode : {BitMode::BIT_1, BitMode::BIT_2, BitMode::BIT_3,
         BitMode::NIBBLE, BitMode::BIT_5, BitMode::BIT_6, BitMode::BYTE,
         BitMode::WORD16, BitMode::WORD32, BitMode::WORD64}) {
        for (size_t n : {size_t(1), size_t(7), size_t(64), size_t(257)}) {
            container_t input(4096, mode);
            std::vector<uint64_t> elements(n);
            const size_t bits = bit_mode_to_size(mode);
            const uint64_t mask = bits == 64 ? ~uint64_t(0) : (uint64_t(1) << bits) - 1;
            for (auto& v : elements) v = ((uint64_t(rng()) << 32) | rng()) & mask;
            input.append_elements(elements.data(), n);
            GeneticCipher<Op> enc, dec;
            configure(enc); configure(dec);
            auto encrypted = enc.encrypt(input);
            auto back = dec.decrypt(encrypted);
            bool ok = back.element_count() == n;
            for (size_t i = 0; i < n; ++i) ok &= back.get_element(i) == elements[i];
            check(ok, std::string(name) + "/" + std::to_string(bits) + "/" + std::to_string(n));
        }
    }
}
int main() {
    roundtrips<Scatter>("Scatter");
    roundtrips<Shuffle>("Shuffle");
    roundtrips<Diffuse>("Diffuse");
    roundtrips<Mix>("Mix");
    roundtrips<Permute>("Permute");
    roundtrips<Rotate>("Rotate");
    roundtrips<Flip>("Flip");
    roundtrips<Swap>("Swap");
    roundtrips<BitwiseNot>("BitwiseNot");
    roundtrips<BitwiseRotL>("BitwiseRotL");
    roundtrips<BitwiseRotR>("BitwiseRotR");
    roundtrips<BitwiseReverse>("BitwiseReverse");
    roundtrips<BitwiseSwapNibbles>("BitwiseSwapNibbles");
    roundtrips<BitwiseGrayCode>("BitwiseGrayCode");
    roundtrips<BitwiseXor>("BitwiseXor");
    roundtrips<BitwiseAnd>("BitwiseAnd");
    roundtrips<BitwiseOr>("BitwiseOr");
    roundtrips<ArithmeticNegate>("ArithmeticNegate");
    roundtrips<ArithmeticAdd>("ArithmeticAdd");
    roundtrips<ArithmeticSub>("ArithmeticSub");
    roundtrips<ArithmeticMul>("ArithmeticMul");
    roundtrips<ArithmeticDiv>("ArithmeticDiv");
    roundtrips<ByteSwap>("ByteSwap");
    roundtrips<ByteReverse>("ByteReverse");
    roundtrips<ByteRotate>("ByteRotate");
    roundtrips<WordSwap>("WordSwap");
    roundtrips<WordMix>("WordMix");
    roundtrips<TransformXorShift>("TransformXorShift");
    roundtrips<TransformChaCha>("TransformChaCha");
    roundtrips<TransformAES>("TransformAES");
    roundtrips<PushMode>("PushMode");
    roundtrips<PopMode>("PopMode");
    roundtrips<SwitchMode>("SwitchMode");
    roundtrips<ModeCycle>("ModeCycle");
    roundtrips<ModeFeedback>("ModeFeedback");
    roundtrips<ChunkPermute>("ChunkPermute");
    roundtrips<ChunkCascade>("ChunkCascade");
    roundtrips<Cascade>("Cascade");
    roundtrips<Spiral>("Spiral");
    roundtrips<Interleave>("Interleave");
    roundtrips<Entangle>("Entangle");
    roundtrips<Avalanche>("Avalanche");
    roundtrips<FractalPermute>("FractalPermute");
    roundtrips<ChaosInject>("ChaosInject");
    roundtrips<BufferMixer>("BufferMixer");
    roundtrips<DualBlockWeave>("DualBlockWeave");
    roundtrips<InstructionCascade>("InstructionCascade");
    roundtrips<StateMachineMix>("StateMachineMix");
    roundtrips<LoopFusion>("LoopFusion");
    roundtrips<BlockResonance>("BlockResonance");
    roundtrips<ParallelScatter>("ParallelScatter");
    roundtrips<ParallelShuffle>("ParallelShuffle");
    roundtrips<ParallelDiffuse>("ParallelDiffuse");
    roundtrips<NoiseWhite>("NoiseWhite");
    roundtrips<NoisePink>("NoisePink");
    roundtrips<NoiseBrown>("NoiseBrown");
    roundtrips<NoiseGaussian>("NoiseGaussian");
    roundtrips<NoiseImpulse>("NoiseImpulse");
    roundtrips<NoiseQuantum>("NoiseQuantum");
    roundtrips<NoiseAdaptive>("NoiseAdaptive");
    roundtrips<NoiseStructured>("NoiseStructured");
    roundtrips<NoiseChaotic>("NoiseChaotic");
    roundtrips<SquareTransform>("SquareTransform");
    roundtrips<CircleTransform>("CircleTransform");
    for (auto mode : {BitMode::BIT_1, BitMode::BIT_2, BitMode::BIT_3,
         BitMode::NIBBLE, BitMode::BIT_5, BitMode::BIT_6, BitMode::BYTE,
         BitMode::WORD16, BitMode::WORD32, BitMode::WORD64}) {
        GeneticCipher<CircleTransform, Scatter, Diffuse, BitwiseXor> enc, dec;
        configure(enc, 128); configure(dec, 128);
        container_t input(4096, mode);
        uint64_t value = 1;
        input.append_elements(&value, 1);
        auto encrypted = enc.encrypt(input);
        check(encrypted.total_bytes() >= 128, "minimum padding/" + std::to_string(bit_mode_to_size(mode)));
        auto back = dec.decrypt(encrypted);
        check(back.get_element(0) == 1, "padded composed pipeline");
        for (size_t i = 1; i < back.element_count(); ++i)
            check(back.get_element(i) == 0, "padding roundtrip");
    }
    for (size_t n : {size_t(1), size_t(31), size_t(256), size_t(4096)}) {
        for (unsigned pattern : {0u, 255u, 256u}) {
            std::vector<uint8_t> bytes(n);
            for (size_t j = 0; j < n; ++j) bytes[j] = pattern == 256 ? uint8_t(j) : uint8_t(pattern);
            container_t input(4096, BitMode::BYTE);
            // Multiple nodes exercise operations across container boundaries.
            for (size_t j = 0; j < n; j += 17)
                input.append_bytes(bytes.data() + j, std::min(size_t(17), n-j));
            using C = GeneticCipher<SquareTransform, CircleTransform, Scatter, Diffuse, BitwiseXor>;
            C enc, dec;
            configure(enc); configure(dec);
            auto ciphertext = enc.encrypt(input);
            check(dec.decrypt(ciphertext).to_bytes() == bytes, "README pipeline binary exact roundtrip");
            check(enc.encrypt(input).to_bytes() == ciphertext.to_bytes(), "repeated calls are deterministic");
        }
    }
    GeneticCipher<Scatter> empty;
    configure(empty);
    try { empty.encrypt(); check(false, "empty encryption rejected"); }
    catch (const std::runtime_error&) { check(true, "empty encryption rejected"); }
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
