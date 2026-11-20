#define STARY_NO_MAIN
#include "main.cpp"

#include <iostream>

namespace {
int failures = 0;

void check(bool value, const char* message) {
    if (!value) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

void write_file(const stary::fs::path& path, const std::string& value) {
    std::ofstream output(path, std::ios::binary);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    if (!output) throw std::runtime_error("test fixture write failed");
}

std::string read_file(const stary::fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void run_tests() {
    using namespace stary;
    const auto root = fs::temp_directory_path() / "stary-tests";
    fs::remove_all(root);
    fs::create_directories(root);
    TemporaryPath cleanup(root);
    auto report = [](const char* name, int failures_before) {
        if (failures == failures_before)
            std::cout << "PASS: " << name << "\n\n";
    };

    const auto password_file = root / "password.txt";
    write_file(password_file, "test password\n");
    Credential password;
    password.password = read_password_file(password_file);
    const auto source = root / "plain.txt";
    const auto encrypted = root / "plain.stary";
    const auto restored = root / "restored.txt";
    const std::string text("Text file round trip: \0 binary-safe", 35);
    write_file(source, text);
    const int file_failures = failures;
    std::vector<unsigned> percentages;
    Progress progress = [&](const std::string&, std::uint64_t done, std::uint64_t total) {
        percentages.push_back(total == 0 ? 100 : static_cast<unsigned>(done * 100 / total));
    };
    encrypt_file(source, encrypted, password, kFileKind,
                 genetic_cipher::BitMode::BYTE, progress);
    decrypt_file(encrypted, restored, password, progress);
    check(read_file(restored) == text, "password-file text round trip");
    check(!percentages.empty() && percentages.back() == 100, "file progress reaches 100 percent");
    report("password-file binary file round trip and progress", file_failures);

    const auto empty_source = root / "empty.txt";
    const auto empty_encrypted = root / "empty.stary";
    const auto empty_restored = root / "empty-restored.txt";
    const int empty_failures = failures;
    write_file(empty_source, "");
    encrypt_file(empty_source, empty_encrypted, password, kFileKind,
                 genetic_cipher::BitMode::BYTE, {});
    decrypt_file(empty_encrypted, empty_restored, password, {});
    check(read_file(empty_restored).empty(), "empty file round trip");
    report("empty file round trip", empty_failures);

    Credential raw_key;
    const auto key_file = root / "key.txt";
    write_file(key_file, std::string(64, '0') + "\n");
    raw_key.raw_key = parse_key_file(key_file);
    const auto key_encrypted = root / "key.stary";
    const auto key_restored = root / "key-restored.txt";
    const int key_failures = failures;
    encrypt_file(source, key_encrypted, raw_key, kFileKind,
                 genetic_cipher::BitMode::BYTE, {});
    decrypt_file(key_encrypted, key_restored, raw_key, {});
    check(read_file(key_restored) == text, "key-file cipher round trip");
    report("raw-key file round trip", key_failures);

    const auto electronic_password_file = root / "electronic-password.txt";
    write_file(electronic_password_file, "secondary electronic password with spaces\n");
    auto electronic_credential = load_credential(password_file, std::nullopt,
                                                  electronic_password_file, false);
    const int electronic_failures = failures;
    check(electronic_credential.electronic_password ==
              std::optional<std::string>("secondary electronic password with spaces"),
          "electronic-password file preserves spaces");
    const auto electronic_token = seal_bytes(Bytes{'s', 'e', 'e', 'd'},
                                               electronic_credential,
                                               genetic_cipher::BitMode::BYTE);
    check(open_bytes(electronic_token, electronic_credential) == Bytes({'s', 'e', 'e', 'd'}),
          "electronic-password file round trip");
    check(electronic_token != seal_bytes(Bytes{'s', 'e', 'e', 'd'}, password,
                                         genetic_cipher::BitMode::BYTE),
          "electronic-password file changes the configured output");
    report("electronic-password file with spaces", electronic_failures);

    const auto directory = root / "input-dir";
    fs::create_directories(directory / "nested");
    write_file(directory / "first.txt", "first file");
    write_file(directory / "nested" / "second.txt", "second file data");
    const auto package = root / "directory.stary";
    const auto extracted = root / "extracted";
    const int directory_failures = failures;
    encrypt_directory(directory, package, password, genetic_cipher::BitMode::BYTE, {});
    decrypt_file(package, extracted, password, {});
    check(read_file(extracted / "first.txt") == "first file", "directory package top-level file");
    check(read_file(extracted / "nested" / "second.txt") == "second file data",
          "directory package nested file");
    report("nested directory package round trip", directory_failures);

    const Bytes plain{'h', 'e', 'l', 'l', 'o'};
    const int text_failures = failures;
    auto token = seal_bytes(plain, password, genetic_cipher::BitMode::BYTE);
    check(open_bytes(token, password) == plain, "terminal text payload round trip");
    token.front() ^= 1;
    bool invalid_envelope_rejected = false;
    try {
        open_bytes(token, password);
    } catch (const std::runtime_error&) {
        invalid_envelope_rejected = true;
    }
    check(invalid_envelope_rejected, "invalid envelope signature is rejected");
    report("terminal text round trip and invalid envelope rejection", text_failures);

    const int width_failures = failures;
    std::set<Bytes> width_outputs;
    for (const auto mode : {genetic_cipher::BitMode::BIT_1, genetic_cipher::BitMode::BIT_2,
                            genetic_cipher::BitMode::BIT_3, genetic_cipher::BitMode::NIBBLE,
                            genetic_cipher::BitMode::BIT_5, genetic_cipher::BitMode::BIT_6,
                            genetic_cipher::BitMode::BYTE, genetic_cipher::BitMode::WORD16,
                            genetic_cipher::BitMode::WORD32, genetic_cipher::BitMode::WORD64}) {
        auto width_token = seal_bytes(plain, password, mode);
        check(open_bytes(width_token, password) == plain,
              "bit-width envelope round trip");
        check(width_token.size() > kEnvelopePrefixSize,
              "bit-width envelope has transformed payload");
        width_outputs.emplace(width_token.begin() + kEnvelopePrefixSize,
                              width_token.end());
    }
    check(width_outputs.size() == 10, "all bit widths produce distinct transformed payloads");
    report("ten bit-width envelope round trips and width-dependent output", width_failures);
}
} // namespace

int main() {
    try {
        run_tests();
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "FAIL: unexpected exception: " << error.what() << '\n';
    }
    std::cout << (failures ? "FAILED" : "PASSED") << " stary tests ("
              << failures << " failures)\n";
    return failures ? 1 : 0;
}
