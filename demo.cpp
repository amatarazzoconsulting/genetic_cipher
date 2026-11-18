// ============================================================================
//  demo_genetic_cipher.cpp
//  A guided tour of genetic_cipher.hpp, written to be read top to bottom.
//
//  Build:  g++ -std=c++20 -O2 -pthread -o demo demo_genetic_cipher.cpp
//  Run:    ./demo
//
//  Every section prints what it is about to do, does it, and checks the result,
//  so you can read the source and watch the output side by side.
// ============================================================================

#include "genetic_cipher.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace genetic_cipher;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
//  Small helpers, so the cipher code below stays readable
// ---------------------------------------------------------------------------
static int g_checks = 0;
static int g_failures = 0;

static void banner(const std::string& title) {
    std::printf("\n\033[1m--- %s ---\033[0m\n", title.c_str());
}

static void expect(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) ++g_failures;
    std::printf("   %s %s\n", ok ? "ok  " : "FAIL", what.c_str());
}

static void note(const std::string& text) {
    std::printf("   %s\n", text.c_str());
}

// Print bytes as hex, wrapped, with a "..." if there are many.
static void hexdump(const std::vector<uint8_t>& bytes, size_t limit = 32) {
    size_t shown = std::min(bytes.size(), limit);
    std::printf("   ");
    for (size_t i = 0; i < shown; ++i) std::printf("%02x ", bytes[i]);
    if (bytes.size() > shown) std::printf("... (%zu bytes total)", bytes.size());
    std::printf("\n");
}

static std::vector<uint8_t> random_bytes(size_t n, uint32_t seed = 1234) {
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(rng() & 0xFF);
    return v;
}

// Fill a container with bytes. This is the one-liner you will use most.
static container_t make_container(const std::vector<uint8_t>& bytes) {
    container_t c(4096, BitMode::BYTE);          // (chunk size hint, element width)
    c.append_bytes(bytes.data(), bytes.size());
    return c;
}

// A typical configuration: both keys set, no minimum-size padding.
template<typename Cipher>
static void configure(Cipher& gc) {
    gc.set_password(std::string("a long user passphrase"));
    gc.set_electronic_password(std::string("device-key-from-secure-storage"));
    gc.settings().minimum_encrypted_size = 0;    // keep demos small
}


// ===========================================================================
//  1. The smallest useful program
// ===========================================================================
//  A cipher is a *type*. You build it by naming the operations you want as
//  template arguments. Decryption is generated for you: every operation in the
//  header is a bijection with a real mathematical inverse, so the cipher knows
//  how to undo its own pipeline in reverse.
// ===========================================================================
static void section_1_hello() {
    banner("1. Encrypt and decrypt a string");

    using SimpleCipher = GeneticCipher<Scatter, Diffuse, Mix, BitwiseXor>;
    SimpleCipher cipher;
    configure(cipher);

    std::string message = "Attack at dawn.";
    std::vector<uint8_t> plain(message.begin(), message.end());

    container_t encrypted = cipher.encrypt(make_container(plain));
    std::vector<uint8_t> cipher_bytes = encrypted.to_bytes();

    note("plaintext  : " + message);
    std::printf("   ciphertext : ");
    hexdump(cipher_bytes);

    container_t decrypted = cipher.decrypt(encrypted);
    std::vector<uint8_t> back = decrypted.to_bytes();
    std::string recovered(back.begin(), back.begin() + static_cast<long>(plain.size()));

    note("recovered  : " + recovered);
    expect(recovered == message, "the round trip gives back the original string");
}


// ===========================================================================
//  2. What a container actually is
// ===========================================================================
//  container_t is the unit of data the cipher works on. It holds a linked list
//  of nodes, and each node has a *bit mode* that says how wide one element is.
//  You fill it with bytes, but the cipher can then treat the same memory as
//  4-bit nibbles, 16-bit words and so on.
// ===========================================================================
static void section_2_container() {
    banner("2. The container: bytes in, elements out");

    auto data = random_bytes(16);
    container_t c = make_container(data);

    std::printf("   ");
    hexdump(data);
    note("total_bytes()   = " + std::to_string(c.total_bytes()));
    note("element_count() = " + std::to_string(c.element_count()) +
         "  (byte mode, so one element per byte)");
    note("global_mode()   = " + std::to_string(bit_mode_to_size(c.global_mode())) + " bits");

    // Element level access. In byte mode element 0 is the first byte.
    uint64_t first = c.get_element(0);
    note("get_element(0)  = " + std::to_string(first) + " (0x" + [&] {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%02llx", static_cast<unsigned long long>(first));
        return std::string(buf);
    }() + ")");
    expect(first == data[0], "element 0 is the first byte");

    // A container is copyable. encrypt() never consumes the one you pass in.
    container_t copy = c.clone();
    copy.set_element(0, 0xFF);
    expect(c.get_element(0) == data[0], "mutating a clone leaves the original alone");

    note("note: encrypt(const container_t&) copies, so your input survives");
}


// ===========================================================================
//  3. Choosing operations
// ===========================================================================
//  The operation list is a menu, not a fixed recipe. More operations means more
//  work per byte. These are the families:
//
//    position : Scatter, Shuffle, Permute, Rotate, Flip, Swap, Spiral,
//               Interleave, ChunkPermute, ChunkCascade, Cascade
//    bits     : BitwiseNot, BitwiseRotL/R, BitwiseReverse, BitwiseXor,
//               BitwiseAnd, BitwiseOr, BitwiseGrayCode, BitwiseSwapNibbles
//    arithmetic: ArithmeticNegate/Add/Sub/Mul/Div
//    words    : ByteSwap, ByteReverse, ByteRotate, WordSwap, WordMix
//    mixing   : Diffuse, Mix, Avalanche, Entangle, ChaosInject, BufferMixer,
//               DualBlockWeave, InstructionCascade, StateMachineMix,
//               LoopFusion, BlockResonance, FractalPermute
//    block    : TransformXorShift, TransformChaCha, TransformAES
//    noise    : NoiseWhite, NoisePink, NoiseBrown, NoiseGaussian,
//               NoiseImpulse, NoiseQuantum, NoiseAdaptive, NoiseStructured,
//               NoiseChaotic
//    parallel : ParallelScatter, ParallelShuffle, ParallelDiffuse
//    mode ops : PushMode, PopMode, SwitchMode, ModeCycle, ModeFeedback
//
//  Order matters: it is part of the key. Two ciphers with the same operations in
//  a different order produce different ciphertext.
// ===========================================================================
static void section_3_operations() {
    banner("3. Building a cipher from operations");

    using Light  = GeneticCipher<Scatter, Diffuse>;
    using Medium = GeneticCipher<Scatter, Shuffle, Diffuse, Mix, TransformChaCha>;
    using Heavy  = GeneticCipher<Scatter, Shuffle, Diffuse, Mix, Permute, Rotate,
                                 BitwiseXor, BitwiseGrayCode, TransformChaCha,
                                 TransformAES, Cascade, Avalanche>;

    auto plain = random_bytes(4096);

    auto timed = [&](const char* label, auto& cipher) {
        configure(cipher);
        auto start = std::chrono::steady_clock::now();
        container_t enc = cipher.encrypt(make_container(plain));
        container_t dec = cipher.decrypt(enc);
        auto ms = std::chrono::duration<double, std::milli>(
                      std::chrono::steady_clock::now() - start).count();
        auto back = dec.to_bytes();
        bool ok = back.size() >= plain.size() &&
                  std::equal(plain.begin(), plain.end(), back.begin());
        std::printf("   %-8s %2zu operations  %7.1f ms for 4 KiB  round trip %s\n",
                    label, std::tuple_size_v<typename std::decay_t<decltype(cipher)>::operation_list>,
                    ms, ok ? "ok" : "FAIL");
        expect(ok, std::string(label) + " round trip");
    };

    Light light; Medium medium; Heavy heavy;
    timed("light", light);
    timed("medium", medium);
    timed("heavy", heavy);

    note("more operations = more mixing, more time. Pick per data sensitivity.");

    // Order is part of the key.
    GeneticCipher<Scatter, Diffuse> order_a;
    GeneticCipher<Diffuse, Scatter> order_b;
    configure(order_a);
    configure(order_b);
    auto a = order_a.encrypt(make_container(plain)).to_bytes();
    auto b = order_b.encrypt(make_container(plain)).to_bytes();
    expect(a != b, "swapping two operations changes the ciphertext");
}


// ===========================================================================
//  4. The two passwords
// ===========================================================================
//  There are two independent secrets:
//    set_password()            - the user's passphrase
//    set_electronic_password() - a device/hardware key, e.g. from a secure
//                                element or a key file on the machine
//  Both are mixed into the key derivation. Decryption needs both to match.
// ===========================================================================
static void section_4_keys() {
    banner("4. Two keys: passphrase plus device key");

    using Cipher = GeneticCipher<Scatter, Diffuse, Mix>;
    auto plain = random_bytes(512);

    Cipher writer;
    configure(writer);
    container_t enc = writer.encrypt(make_container(plain));

    Cipher reader;
    reader.set_password(std::string("a long user passphrase"));
    reader.set_electronic_password(std::string("device-key-from-secure-storage"));
    reader.settings().minimum_encrypted_size = 0;
    auto ok_bytes = reader.decrypt(enc).to_bytes();
    expect(ok_bytes.size() >= plain.size() &&
           std::equal(plain.begin(), plain.end(), ok_bytes.begin()),
           "both keys matching decrypts correctly");

    Cipher wrong_device;
    wrong_device.set_password(std::string("a long user passphrase"));
    wrong_device.set_electronic_password(std::string("some-other-device"));
    wrong_device.settings().minimum_encrypted_size = 0;
    auto bad = wrong_device.decrypt(enc).to_bytes();
    bool leaked = bad.size() >= plain.size() &&
                  std::equal(plain.begin(), plain.end(), bad.begin());
    expect(!leaked, "a wrong device key does not recover the plaintext");

    note("a wrong key yields garbage, not an error. See section 10.");
}


// ===========================================================================
//  5. Settings worth knowing
// ===========================================================================
//  settings() returns a reference to the live EncryptionSettings struct. Change
//  it before you encrypt. The ones that affect output most:
//
//    minimum_encrypted_size  pad short inputs up to this many bytes (4096
//                            by default, so a 12-byte message still writes a
//                            4 KiB blob and hides its real length)
//    diffusion_rounds        how hard Diffuse works (default 10)
//    scatter_passes          passes for Scatter / Shuffle
//    bit_mode                element width for the whole pipeline
//    noise_level             strength of the noise operations, 0.0 - 1.0
// ===========================================================================
static void section_5_settings() {
    banner("5. Settings");

    using Cipher = GeneticCipher<Scatter, Diffuse, Mix>;

    Cipher padded;
    configure(padded);
    padded.settings().minimum_encrypted_size = 4096;
    auto small = random_bytes(12);
    auto padded_bytes = padded.encrypt(make_container(small)).to_bytes();
    note("12-byte message with minimum_encrypted_size = 4096 -> " +
         std::to_string(padded_bytes.size()) + " bytes of ciphertext");
    expect(padded_bytes.size() >= 4096, "short input is padded up to the minimum");
    auto back = padded.decrypt(make_container(padded_bytes)).to_bytes();
    expect(std::equal(small.begin(), small.end(), back.begin()),
           "padding is reversible; your original prefix comes back first");

    // Diffusion strength.
    Cipher weak, strong;
    configure(weak);
    configure(strong);
    weak.settings().diffusion_rounds = 1;
    strong.settings().diffusion_rounds = 10;

    auto plain = random_bytes(2048);
    auto a = weak.encrypt(make_container(plain)).to_bytes();
    auto b = strong.encrypt(make_container(plain)).to_bytes();
    note("diffusion_rounds = 1  -> " + std::to_string(a.size()) + " bytes");
    note("diffusion_rounds = 10 -> " + std::to_string(b.size()) + " bytes");
    expect(a != b, "diffusion_rounds changes the output");

    note("settings are read at encrypt time, so set them before you start");
}


// ===========================================================================
//  6. Bit modes
// ===========================================================================
//  The same memory can be processed as 1, 2, 3, 4, 5, 6, 8, 16, 32 or 64 bit
//  elements. Narrow modes make the position and bit operations work on a much
//  finer grain. The payload is still bytes on disk; only the internal view of
//  the data changes.
// ===========================================================================
static void section_6_bit_modes() {
    banner("6. Bit modes");

    using Cipher = GeneticCipher<Scatter, Diffuse, BitwiseGrayCode>;

    auto plain = random_bytes(1024);
    for (BitMode mode : {BitMode::NIBBLE, BitMode::BYTE, BitMode::WORD16, BitMode::WORD64}) {
        Cipher gc;
        configure(gc);
        gc.settings().bit_mode = mode;

        container_t in(4096, mode);
        in.append_bytes(plain.data(), plain.size());

        container_t enc = gc.encrypt(in);
        container_t dec = gc.decrypt(enc);
        auto back = dec.to_bytes();
        bool ok = back.size() >= plain.size() &&
                  std::equal(plain.begin(), plain.end(), back.begin());
        std::printf("   %2zu-bit elements: %zu elements, round trip %s\n",
                    bit_mode_to_size(mode), in.element_count(), ok ? "ok" : "FAIL");
        expect(ok, std::to_string(bit_mode_to_size(mode)) + "-bit round trip");
    }

    note("BYTE is the safe default. Narrow modes are for when you want the");
    note("operations to work on small units, and they cost more time per byte.");

    // Reading the same bytes at a chosen width: build the container in that mode.
    container_t bytes_view(4096, BitMode::BYTE);
    bytes_view.append_bytes(std::vector<uint8_t>{0x12, 0x34, 0x56, 0x78}.data(), 4);
    container_t words_view(4096, BitMode::WORD16);
    words_view.append_bytes(std::vector<uint8_t>{0x12, 0x34, 0x56, 0x78}.data(), 4);
    note("12 34 56 78 as 8-bit elements : " + std::to_string(bytes_view.get_element(0)) +
         " " + std::to_string(bytes_view.get_element(1)) + " ...");
    note("12 34 56 78 as 16-bit elements: " + std::to_string(words_view.get_element(0)) +
         " " + std::to_string(words_view.get_element(1)));
    expect(words_view.get_element(0) == 0x1234 && words_view.get_element(1) == 0x5678,
           "the same bytes read as two 16-bit words");
}


// ===========================================================================
//  7. Files and archives
// ===========================================================================
//  For more than one blob you queue files and write a single archive. The
//  archive carries a directory of names, sizes and offsets, so extraction puts
//  the original files back with their original names.
// ===========================================================================
static void section_7_files() {
    banner("7. Files and archives");

    fs::path dir = fs::temp_directory_path() / "genetic_cipher_demo";
    fs::remove_all(dir);
    fs::create_directories(dir);

    auto notes = random_bytes(1200, 11);
    auto report = random_bytes(300, 12);

    {   // write the two source files
        std::ofstream(dir / "notes.txt", std::ios::binary)
            .write(reinterpret_cast<const char*>(notes.data()),
                   static_cast<std::streamsize>(notes.size()));
        std::ofstream(dir / "report.bin", std::ios::binary)
            .write(reinterpret_cast<const char*>(report.data()),
                   static_cast<std::streamsize>(report.size()));
    }

    using Cipher = GeneticCipher<Scatter, Shuffle, Diffuse, Mix, TransformAES>;

    Cipher writer;
    configure(writer);
    writer.add_input_file((dir / "notes.txt").string());
    writer.add_input_file((dir / "report.bin").string());
    writer.save_encrypted((dir / "bundle.gc").string());
    note("wrote " + (dir / "bundle.gc").string() + " (" +
         std::to_string(fs::file_size(dir / "bundle.gc")) + " bytes)");
    expect(fs::exists(dir / "bundle.gc"), "archive written");

    // Read it back with a fresh object.
    Cipher reader;
    configure(reader);
    reader.load_encrypted((dir / "bundle.gc").string());

    auto names = reader.directory().list_files();
    std::sort(names.begin(), names.end());
    note("archive contains:");
    for (const auto& name : names) {
        auto entry = reader.directory().get_file(name);
        std::printf("   %-12s %6llu bytes\n", name.c_str(),
                    static_cast<unsigned long long>(entry.original_size));
    }
    expect(names.size() == 2, "both files are recorded in the directory");

    reader.extract_all_files((dir / "out").string());

    auto same = [](const fs::path& path, const std::vector<uint8_t>& want) {
        std::ifstream in(path, std::ios::binary);
        std::vector<uint8_t> got((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
        return got == want;
    };
    expect(same(dir / "out" / "notes.txt", notes), "notes.txt came back byte for byte");
    expect(same(dir / "out" / "report.bin", report), "report.bin came back byte for byte");

    // One file at a time.
    reader.extract_file("notes.txt", (dir / "just_notes.txt").string());
    expect(same(dir / "just_notes.txt", notes), "extract_file pulls a single file out");

    fs::remove_all(dir);
    note("add_input_file() queues, save_encrypted() writes, extract_*() restores");
}


// ===========================================================================
//  8. Streaming with progress
// ===========================================================================
//  Same archive format, but with a progress callback so a UI can show a bar.
//  encrypt_streaming() and decrypt_streaming() are a matched pair.
// ===========================================================================
static void section_8_streaming() {
    banner("8. Streaming with a progress callback");

    fs::path dir = fs::temp_directory_path() / "genetic_cipher_demo_stream";
    fs::remove_all(dir);
    fs::create_directories(dir);

    auto payload = random_bytes(64 * 1024, 21);
    std::ofstream(dir / "big.bin", std::ios::binary)
        .write(reinterpret_cast<const char*>(payload.data()),
               static_cast<std::streamsize>(payload.size()));

    using Cipher = GeneticCipher<Scatter, Shuffle, Diffuse, Mix, TransformChaCha>;

    Cipher writer;
    configure(writer);
    writer.add_input_file((dir / "big.bin").string());

    float progress = -1.0f;
    writer.encrypt_streaming((dir / "big.gc").string(),
                             [&](float f) { progress = f; });
    note("encrypt_streaming reported progress " + std::to_string(progress));
    expect(progress == 1.0f, "encryption reached 100%");

    Cipher reader;
    configure(reader);
    float read_progress = -1.0f;
    reader.decrypt_streaming((dir / "big.gc").string(),
                             (dir / "out").string(),
                             [&](float f) { read_progress = f; });
    expect(read_progress == 1.0f, "decryption reached 100%");

    std::ifstream in(dir / "out" / "big.bin", std::ios::binary);
    std::vector<uint8_t> got((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    expect(got == payload, "64 KiB file came back intact");

    fs::remove_all(dir);
    note("for a real progress bar, drive the callback from a worker thread");
}


// ===========================================================================
//  9. What goes wrong, and how it is reported
// ===========================================================================
//  The header throws std::runtime_error for misuse: encrypting nothing,
//  reading a file that is not there, opening an archive that is corrupt.
//  Catch it and show the message; the messages are written for humans.
// ===========================================================================
static void section_9_errors() {
    banner("9. Error handling");

    using Cipher = GeneticCipher<Scatter, Diffuse>;
    Cipher gc;
    configure(gc);

    // Encrypting an empty container.
    try {
        container_t empty(4096, BitMode::BYTE);
        gc.encrypt(empty);
        expect(false, "encrypting an empty container should have thrown");
    } catch (const std::runtime_error& e) {
        note(std::string("empty container -> ") + e.what());
        expect(true, "empty container is rejected");
    }

    // A file that does not exist.
    try {
        gc.add_input_file("/definitely/not/here.bin");
        expect(false, "a missing input file should have thrown");
    } catch (const std::runtime_error& e) {
        note(std::string("missing file -> ") + e.what());
        expect(true, "missing input file is rejected");
    }

    // A file that is not an archive.
    fs::path junk = fs::temp_directory_path() / "genetic_cipher_demo_junk.gc";
    { std::ofstream(junk, std::ios::binary) << "this is not an archive"; }
    try {
        gc.load_encrypted(junk.string());
        expect(false, "loading junk should have thrown");
    } catch (const std::exception& e) {
        note(std::string("junk archive -> ") + e.what());
        expect(true, "a corrupt archive is rejected");
    }
    fs::remove(junk);
}


// ===========================================================================
//  10. Determinism, tampering, and what this does not do
// ===========================================================================
//  Same keys and same input always give the same ciphertext. That is what makes
//  the format testable, and it is also a property to be aware of: identical
//  plaintexts produce identical ciphertexts, so this is not a randomised
//  encryption scheme.
//
//  Tampering: a flipped ciphertext byte decrypts to garbage rather than raising
//  an error. The archive directory has an integrity hash, but the payload is not
//  authenticated. If you need to detect tampering, add a MAC or a signature over
//  the ciphertext.
// ===========================================================================
static void section_10_determinism() {
    banner("10. Determinism, tampering, and limits");

    using Cipher = GeneticCipher<Scatter, Diffuse, Mix>;
    auto plain = random_bytes(1024, 33);

    Cipher a, b;
    configure(a);
    configure(b);
    auto ca = a.encrypt(make_container(plain)).to_bytes();
    auto cb = b.encrypt(make_container(plain)).to_bytes();
    expect(ca == cb, "same keys and same input give identical ciphertext");

    auto flipped = ca;
    flipped[flipped.size() / 2] ^= 0x01;
    auto broken = a.decrypt(make_container(flipped)).to_bytes();
    bool leaked = broken.size() >= plain.size() &&
                  std::equal(plain.begin(), plain.end(), broken.begin());
    expect(!leaked, "a flipped ciphertext bit does not decrypt to the original");
    note("that is silent corruption, not an error: add a MAC if you need to detect it");

    note("also note: identical plaintexts produce identical ciphertexts,");
    note("so this is deterministic encryption, not randomised encryption.");
}


// ===========================================================================
//  11. Measuring throughput
// ===========================================================================
//  Encryption runs about 200 KB/s with the full operation set on one core, so
//  measure before you promise a number. Time a 1 MiB payload and scale.
// ===========================================================================
static void section_11_performance() {
    banner("11. Measuring throughput");

    using Cipher = GeneticCipher<Scatter, Shuffle, Diffuse, Mix, BitwiseXor,
                                 TransformChaCha, Cascade>;
    Cipher gc;
    configure(gc);

    size_t size = 256 * 1024;              // 256 KiB is enough to get a stable rate
    auto plain = random_bytes(size, 44);

    auto t0 = std::chrono::steady_clock::now();
    container_t enc = gc.encrypt(make_container(plain));
    auto t1 = std::chrono::steady_clock::now();
    container_t dec = gc.decrypt(enc);
    auto t2 = std::chrono::steady_clock::now();

    double enc_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double dec_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
    double kb = static_cast<double>(size) / 1024.0;

    std::printf("   %zu KiB: encrypt %.1f ms (%.0f KB/s), decrypt %.1f ms (%.0f KB/s)\n",
                size / 1024, enc_ms, kb / (enc_ms / 1000.0),
                dec_ms, kb / (dec_ms / 1000.0));

    auto back = dec.to_bytes();
    expect(back.size() >= plain.size() && std::equal(plain.begin(), plain.end(), back.begin()),
           "the timed round trip is correct");

    note("cost is per element, so narrower bit modes cost more per byte");
    note("and every extra operation adds a full pass over the data");
}


// ===========================================================================
//  Main
// ===========================================================================
int main() {
    std::printf("genetic_cipher %u.%u.%u - guided demo\n",
                VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    section_1_hello();
    section_2_container();
    section_3_operations();
    section_4_keys();
    section_5_settings();
    section_6_bit_modes();
    section_7_files();
    section_8_streaming();
    section_9_errors();
    section_10_determinism();
    section_11_performance();

    std::printf("\n----------------------------------------\n");
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    std::printf("%s\n", g_failures == 0 ? "DEMO COMPLETED CLEANLY" : "DEMO HAD FAILURES");
    return g_failures == 0 ? 0 : 1;
}
