#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../genetic_cipher.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace stary {
namespace fs = std::filesystem;

using Bytes = std::vector<std::uint8_t>;
using Progress = std::function<void(const std::string&, std::uint64_t, std::uint64_t)>;
using CipherEngine = genetic_cipher::GeneticCipher<
    genetic_cipher::PushMode,
    genetic_cipher::SquareTransform,
    genetic_cipher::Scatter,
    genetic_cipher::PopMode,
    genetic_cipher::PushMode,
    genetic_cipher::CircleTransform,
    genetic_cipher::Shuffle,
    genetic_cipher::PopMode,
    genetic_cipher::PushMode,
    genetic_cipher::TriangleTransform,
    genetic_cipher::Diffuse,
    genetic_cipher::PopMode,
    genetic_cipher::PushMode,
    genetic_cipher::Mix,
    genetic_cipher::TransformChaCha,
    genetic_cipher::PopMode>;

constexpr std::array<std::uint8_t, 8> kEnvelopeMagic{'S','T','G','C','0','0','0','2'};
constexpr std::array<std::uint8_t, 8> kPackageMagic{'S','T','P','K','G','0','0','1'};
constexpr std::size_t kBufferSize = 64 * 1024;
constexpr std::size_t kEnvelopePrefixSize = kEnvelopeMagic.size() + 2 + sizeof(std::uint64_t);
constexpr std::uint8_t kFileKind = 0;
constexpr std::uint8_t kDirectoryKind = 1;

struct Credential {
    std::string password;
    std::optional<std::array<std::uint8_t, 32>> raw_key;
    std::optional<std::string> electronic_password;
};

class TemporaryPath {
public:
    explicit TemporaryPath(fs::path path) : path_(std::move(path)) {}
    TemporaryPath(const TemporaryPath&) = delete;
    TemporaryPath& operator=(const TemporaryPath&) = delete;
    ~TemporaryPath() {
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }
    const fs::path& path() const { return path_; }
    void release() { path_.clear(); }
private:
    fs::path path_;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void require(bool condition, const std::string& message) {
    if (!condition) fail(message);
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
        result << std::setw(2) << static_cast<unsigned>(data[i]);
    return result.str();
}

std::optional<std::array<std::uint8_t, 32>> parse_key_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.good(), "Cannot open key file: " + path.string());
    std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.pop_back();
    auto first = std::find_if_not(text.begin(), text.end(), [](unsigned char ch) {
        return std::isspace(ch);
    });
    text.erase(text.begin(), first);
    require(text.size() == 64, "Key file must contain exactly 64 hexadecimal characters");
    std::array<std::uint8_t, 32> key{};
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < key.size(); ++i) {
        const int hi = nibble(text[i * 2]);
        const int lo = nibble(text[i * 2 + 1]);
        require(hi >= 0 && lo >= 0, "Key file contains a non-hexadecimal character");
        key[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return key;
}

std::string read_password_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.good(), "Cannot open password file: " + path.string());
    std::string password;
    std::getline(input, password);
    require(input.eof() || input.good(), "Cannot read password file: " + path.string());
    if (!password.empty() && password.back() == '\r') password.pop_back();
    require(!password.empty(), "Password file is empty");
    return password;
}

std::string prompt_password(bool confirm) {
    auto read_line = [](const char* prompt) {
        std::cerr << prompt << std::flush;
#ifndef _WIN32
        termios previous{};
        const bool changed = (isatty(STDIN_FILENO) == 1 &&
                              tcgetattr(STDIN_FILENO, &previous) == 0);
        if (changed) {
            termios hidden = previous;
            hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden);
        }
#endif
        std::string line;
        std::getline(std::cin, line);
#ifndef _WIN32
        if (changed) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &previous);
            std::cerr << '\n';
        }
#endif
        require(std::cin.good() || std::cin.eof(), "Could not read password");
        require(!line.empty(), "Password must not be empty");
        return line;
    };
    auto password = read_line("Password: ");
    if (confirm) {
        auto repeated = read_line("Confirm password: ");
        require(password == repeated, "Passwords do not match");
    }
    return password;
}

Credential load_credential(const std::optional<fs::path>& password_file,
                           const std::optional<fs::path>& key_file,
                           const std::optional<fs::path>& electronic_password_file,
                           bool confirm_password) {
    require(!(password_file && key_file), "Choose either --password-file or --key-file");
    Credential credential;
    if (password_file) {
        credential.password = read_password_file(*password_file);
    } else if (key_file) {
        credential.raw_key = parse_key_file(*key_file);
    } else {
        credential.password = prompt_password(confirm_password);
    }
    if (electronic_password_file)
        credential.electronic_password = read_password_file(*electronic_password_file);
    return credential;
}

genetic_cipher::BitMode parse_bit_width(const std::string& width) {
    using genetic_cipher::BitMode;
    if (width == "1") return BitMode::BIT_1;
    if (width == "2") return BitMode::BIT_2;
    if (width == "3") return BitMode::BIT_3;
    if (width == "4") return BitMode::NIBBLE;
    if (width == "5") return BitMode::BIT_5;
    if (width == "6") return BitMode::BIT_6;
    if (width == "8") return BitMode::BYTE;
    if (width == "16") return BitMode::WORD16;
    if (width == "32") return BitMode::WORD32;
    if (width == "64") return BitMode::WORD64;
    fail("Bit width must be one of: 1, 2, 3, 4, 5, 6, 8, 16, 32, 64");
}

fs::path make_temp_file(const fs::path& target) {
    const fs::path parent = target.parent_path().empty() ? fs::current_path() : target.parent_path();
    require(fs::exists(parent) && fs::is_directory(parent),
            "Output directory does not exist: " + parent.string());
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::array<std::uint8_t, 12> random{};
        require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1,
                "Could not generate a temporary filename");
        const auto candidate = parent / (target.filename().string() + ".stary-" +
                                         hex_encode(random.data(), random.size()) + ".tmp");
#ifndef _WIN32
        const int fd = ::open(candidate.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd >= 0) {
            ::close(fd);
            return candidate;
        }
#else
        if (!fs::exists(candidate)) {
            std::ofstream create(candidate, std::ios::binary);
            if (create) return candidate;
        }
#endif
    }
    fail("Could not create a temporary output file");
}

fs::path make_temp_directory(const fs::path& target) {
    const fs::path parent = target.parent_path().empty() ? fs::current_path() : target.parent_path();
    require(fs::exists(parent) && fs::is_directory(parent),
            "Output directory does not exist: " + parent.string());
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::array<std::uint8_t, 12> random{};
        require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1,
                "Could not generate a temporary directory name");
        auto candidate = parent / (target.filename().string() + ".stary-" +
                                   hex_encode(random.data(), random.size()) + ".tmpdir");
        std::error_code error;
        if (fs::create_directory(candidate, error)) return candidate;
    }
    fail("Could not create a temporary output directory");
}

void report_progress(const Progress& progress, const std::string& label,
                     std::uint64_t done, std::uint64_t total) {
    if (progress) progress(label, done, total);
}

void configure_engine(CipherEngine& cipher, const Credential& credential,
                      genetic_cipher::BitMode bit_mode) {
    const std::string password = credential.raw_key
        ? std::string(reinterpret_cast<const char*>(credential.raw_key->data()),
                      credential.raw_key->size())
        : credential.password;
    cipher.set_password(password);
    cipher.set_electronic_password(
        credential.electronic_password.value_or("stary-header-engine-v1"));
    cipher.settings().bit_mode = bit_mode;
    cipher.settings().minimum_encrypted_size = 0;
}

void encrypt_stream(std::istream& source, std::ostream& destination,
                    std::uint64_t total, const std::string& label,
                    const Credential& credential, std::uint8_t kind,
                    genetic_cipher::BitMode bit_mode,
                    const Progress& progress) {
    require(total <= std::numeric_limits<std::size_t>::max(),
            "Input is too large for the genetic cipher engine");
    require(total <= static_cast<std::uint64_t>(
                std::numeric_limits<std::streamsize>::max()),
            "Input is too large to read");
    Bytes plain(static_cast<std::size_t>(total));
    if (!plain.empty()) {
        source.read(reinterpret_cast<char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
        require(source.gcount() == static_cast<std::streamsize>(plain.size()),
                "Could not read the complete input");
    }
    require(source.peek() == EOF, "Input changed while it was being read");

    require(plain.size() <= std::numeric_limits<std::size_t>::max() - sizeof(std::uint64_t),
            "Input is too large for the genetic cipher engine");
    Bytes payload(sizeof(std::uint64_t) + plain.size());
    const auto plain_size = static_cast<std::uint64_t>(plain.size());
    for (std::size_t i = 0; i < sizeof(plain_size); ++i)
        payload[i] = static_cast<std::uint8_t>(plain_size >> (i * 8));
    std::copy(plain.begin(), plain.end(), payload.begin() + sizeof(plain_size));

    CipherEngine cipher;
    configure_engine(cipher, credential, bit_mode);
    genetic_cipher::container_t input(kBufferSize, bit_mode);
    input.append_bytes(payload.data(), payload.size());
    auto encrypted_container = cipher.encrypt(input);
    auto encrypted = encrypted_container.to_bytes();
    require(encrypted.size() <= static_cast<std::size_t>(
                std::numeric_limits<std::streamsize>::max()),
            "Encrypted output is too large to write");

    report_progress(progress, label, 0, total);
    destination.write(reinterpret_cast<const char*>(kEnvelopeMagic.data()),
                      static_cast<std::streamsize>(kEnvelopeMagic.size()));
    destination.put(static_cast<char>(kind));
    destination.put(static_cast<char>(genetic_cipher::bit_mode_to_size(bit_mode)));
    const auto element_count = static_cast<std::uint64_t>(encrypted_container.element_count());
    for (std::size_t i = 0; i < sizeof(element_count); ++i)
        destination.put(static_cast<char>(element_count >> (i * 8)));
    destination.write(reinterpret_cast<const char*>(encrypted.data()),
                      static_cast<std::streamsize>(encrypted.size()));
    require(destination.good(), "Could not write encrypted output");
    report_progress(progress, label, total, total);
}

std::uint8_t decrypt_stream(std::istream& source, std::ostream& destination,
                            std::uint64_t total_file_size, const std::string& label,
                            const Credential& credential, const Progress& progress) {
    require(total_file_size >= kEnvelopePrefixSize + sizeof(std::uint64_t),
            "Encrypted file is truncated");
    std::array<std::uint8_t, kEnvelopePrefixSize> prefix{};
    source.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
    require(source.gcount() == static_cast<std::streamsize>(prefix.size()) &&
            std::equal(kEnvelopeMagic.begin(), kEnvelopeMagic.end(), prefix.begin()),
            "Input is not a stary genetic-cipher file");
    const auto kind = prefix[kEnvelopeMagic.size()];
    require(kind == kFileKind || kind == kDirectoryKind, "Unknown encrypted payload type");
    const auto bit_mode = parse_bit_width(std::to_string(prefix[kEnvelopeMagic.size() + 1]));
    std::uint64_t element_count = 0;
    for (std::size_t i = 0; i < sizeof(element_count); ++i)
        element_count |= static_cast<std::uint64_t>(
            prefix[kEnvelopeMagic.size() + 2 + i]) << (i * 8);
    require(element_count > 0 && element_count <= std::numeric_limits<std::size_t>::max(),
            "Encrypted file has an invalid element count");

    const auto encrypted_size = total_file_size - kEnvelopePrefixSize;
    require(encrypted_size <= std::numeric_limits<std::size_t>::max(),
            "Encrypted file is too large for the genetic cipher engine");
    require(encrypted_size <= static_cast<std::uint64_t>(
                std::numeric_limits<std::streamsize>::max()),
            "Encrypted file is too large to read");
    Bytes encrypted(static_cast<std::size_t>(encrypted_size));
    source.read(reinterpret_cast<char*>(encrypted.data()),
                static_cast<std::streamsize>(encrypted.size()));
    require(source.gcount() == static_cast<std::streamsize>(encrypted.size()) &&
            source.peek() == EOF, "Encrypted file is truncated or changed while being read");

    CipherEngine cipher;
    configure_engine(cipher, credential, bit_mode);
    genetic_cipher::container_t input(kBufferSize, bit_mode);
    input.append_packed_bytes(encrypted.data(), encrypted.size(),
                              static_cast<std::size_t>(element_count));
    auto plain = cipher.decrypt(input).to_bytes();
    require(plain.size() >= sizeof(std::uint64_t), "Decrypted payload is truncated");
    std::uint64_t plain_size = 0;
    for (std::size_t i = 0; i < sizeof(plain_size); ++i)
        plain_size |= static_cast<std::uint64_t>(plain[i]) << (i * 8);
    require(plain_size <= plain.size() - sizeof(plain_size),
            "Decrypted payload has an invalid length");
    require(plain_size <= static_cast<std::uint64_t>(
                std::numeric_limits<std::streamsize>::max()),
            "Decrypted payload is too large to write");

    report_progress(progress, label, 0, plain_size);
    destination.write(reinterpret_cast<const char*>(plain.data() + sizeof(plain_size)),
                      static_cast<std::streamsize>(plain_size));
    require(destination.good(), "Could not write decrypted data");
    report_progress(progress, label, plain_size, plain_size);
    return kind;
}

void encrypt_file(const fs::path& input_path, const fs::path& output_path,
                  const Credential& credential, std::uint8_t kind,
                  genetic_cipher::BitMode bit_mode,
                  const Progress& progress) {
    require(fs::is_regular_file(input_path), "Input is not a regular file: " + input_path.string());
    require(fs::absolute(input_path).lexically_normal() != fs::absolute(output_path).lexically_normal(),
            "Input and output paths must be different");
    require(!fs::exists(output_path), "Output already exists: " + output_path.string());
    std::ifstream input(input_path, std::ios::binary);
    require(input.good(), "Cannot open input file: " + input_path.string());
    const auto total = fs::file_size(input_path);
    auto temporary = make_temp_file(output_path);
    TemporaryPath cleanup(temporary);
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    require(output.good(), "Cannot open temporary output file");
    encrypt_stream(input, output, total, input_path.filename().string(), credential,
                   kind, bit_mode, progress);
    output.close();
    require(output.good(), "Could not close encrypted output");
    fs::rename(temporary, output_path);
    cleanup.release();
}

std::uint8_t decrypt_file_to_temp(const fs::path& input_path, const fs::path& temporary,
                                 const Credential& credential, const Progress& progress) {
    std::ifstream input(input_path, std::ios::binary);
    require(input.good(), "Cannot open encrypted file: " + input_path.string());
    const auto total = fs::file_size(input_path);
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    require(output.good(), "Cannot open temporary decrypted output");
    const auto kind = decrypt_stream(input, output, total, input_path.filename().string(),
                                     credential, progress);
    output.close();
    require(output.good(), "Could not close decrypted output");
    return kind;
}

void write_u32(std::ostream& output, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) output.put(static_cast<char>((value >> (i * 8)) & 0xff));
}

void write_u64(std::ostream& output, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) output.put(static_cast<char>((value >> (i * 8)) & 0xff));
}

std::uint32_t read_u32(std::istream& input) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        const int byte = input.get();
        require(byte != EOF, "Directory package is truncated");
        value |= static_cast<std::uint32_t>(byte) << (i * 8);
    }
    return value;
}

std::uint64_t read_u64(std::istream& input) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        const int byte = input.get();
        require(byte != EOF, "Directory package is truncated");
        value |= static_cast<std::uint64_t>(byte) << (i * 8);
    }
    return value;
}

struct PackageEntry {
    fs::path path;
    std::string name;
    std::uint64_t size;
};

void create_package(const fs::path& directory, const fs::path& package_path,
                    const Progress& progress) {
    require(fs::is_directory(directory) && !fs::is_symlink(directory),
            "Input directory must be a real directory");
    std::vector<PackageEntry> entries;
    std::uint64_t total = 0;
    for (const auto& item : fs::recursive_directory_iterator(directory)) {
        if (fs::is_symlink(item.symlink_status()))
            fail("Symbolic links are not included in directory packages: " + item.path().string());
        if (!item.is_regular_file()) continue;
        auto relative = item.path().lexically_relative(directory).generic_string();
        require(!relative.empty() && relative.size() <= 4096,
                "Directory contains an invalid or overly long path");
        const auto size = item.file_size();
        require(size <= std::numeric_limits<std::uint64_t>::max() - total,
                "Directory package is too large");
        total += size;
        entries.push_back({item.path(), std::move(relative), size});
        require(entries.size() <= 100000, "Directory has too many files (maximum 100000)");
    }

    std::ofstream output(package_path, std::ios::binary | std::ios::trunc);
    require(output.good(), "Could not create directory package");
    output.write(reinterpret_cast<const char*>(kPackageMagic.data()), kPackageMagic.size());
    write_u32(output, static_cast<std::uint32_t>(entries.size()));
    report_progress(progress, "Packaging directory", 0, total);
    std::array<char, kBufferSize> buffer{};
    std::uint64_t done = 0;
    for (const auto& entry : entries) {
        std::ifstream input(entry.path, std::ios::binary);
        require(input.good(), "Cannot read directory member: " + entry.path.string());
        write_u32(output, static_cast<std::uint32_t>(entry.name.size()));
        write_u64(output, entry.size);
        output.write(entry.name.data(), static_cast<std::streamsize>(entry.name.size()));
        std::uint64_t file_done = 0;
        report_progress(progress, entry.name, 0, entry.size);
        while (file_done < entry.size) {
            const auto wanted = static_cast<std::streamsize>(
                std::min<std::uint64_t>(buffer.size(), entry.size - file_done));
            input.read(buffer.data(), wanted);
            require(input.gcount() == wanted, "Directory member changed while packaging: " +
                    entry.path.string());
            output.write(buffer.data(), wanted);
            require(output.good(), "Could not write directory package");
            file_done += static_cast<std::uint64_t>(wanted);
            done += static_cast<std::uint64_t>(wanted);
            report_progress(progress, entry.name, file_done, entry.size);
            report_progress(progress, "Packaging directory", done, total);
        }
    }
    require(output.good(), "Could not finish directory package");
    report_progress(progress, "Packaging directory", total, total);
}

bool is_safe_relative_path(const std::string& name) {
    if (name.empty() || name.size() > 4096 || name.find('\0') != std::string::npos)
        return false;
    const fs::path path(name);
    if (path.is_absolute() || path.has_root_name() || path.has_root_directory())
        return false;
    for (const auto& part : path)
        if (part == ".." || part == "." || part.empty()) return false;
    return true;
}

void extract_package(const fs::path& package_path, const fs::path& output_directory,
                     const Progress& progress) {
    require(!fs::exists(output_directory),
            "Output directory already exists: " + output_directory.string());
    std::ifstream input(package_path, std::ios::binary);
    require(input.good(), "Could not open decrypted directory package");
    std::array<std::uint8_t, 8> magic{};
    input.read(reinterpret_cast<char*>(magic.data()), magic.size());
    require(input.gcount() == static_cast<std::streamsize>(magic.size()) &&
            magic == kPackageMagic, "Decrypted directory package has an invalid signature");
    const auto count = read_u32(input);
    require(count <= 100000, "Directory package has too many entries");
    auto staging_path = make_temp_directory(output_directory);
    TemporaryPath cleanup(staging_path);
    std::set<std::string> seen;
    std::uint64_t total = 0;
    std::uint64_t done = 0;
    std::array<char, kBufferSize> buffer{};
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto name_size = read_u32(input);
        const auto file_size = read_u64(input);
        require(name_size > 0 && name_size <= 4096, "Invalid path length in directory package");
        std::string name(name_size, '\0');
        input.read(name.data(), static_cast<std::streamsize>(name_size));
        require(input.gcount() == static_cast<std::streamsize>(name_size),
                "Directory package is truncated");
        require(is_safe_relative_path(name), "Unsafe path in directory package");
        require(seen.insert(name).second, "Duplicate path in directory package");
        require(file_size <= std::numeric_limits<std::uint64_t>::max() - total,
                "Directory package is too large");
        total += file_size;
        const auto destination = staging_path / fs::path(name);
        fs::create_directories(destination.parent_path());
        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        require(output.good(), "Could not create extracted file: " + name);
        std::uint64_t file_done = 0;
        report_progress(progress, name, 0, file_size);
        while (file_done < file_size) {
            const auto wanted = static_cast<std::streamsize>(
                std::min<std::uint64_t>(buffer.size(), file_size - file_done));
            input.read(buffer.data(), wanted);
            require(input.gcount() == wanted, "Directory package is truncated");
            output.write(buffer.data(), wanted);
            require(output.good(), "Could not write extracted file: " + name);
            file_done += static_cast<std::uint64_t>(wanted);
            done += static_cast<std::uint64_t>(wanted);
            report_progress(progress, name, file_done, file_size);
        }
        output.close();
        require(output.good(), "Could not close extracted file: " + name);
    }
    require(input.peek() == EOF, "Directory package contains trailing data");
    fs::rename(staging_path, output_directory);
    cleanup.release();
    report_progress(progress, "Extracting directory", total, total);
}

void encrypt_directory(const fs::path& input_directory, const fs::path& output_path,
                       const Credential& credential, genetic_cipher::BitMode bit_mode,
                       const Progress& progress) {
    require(fs::absolute(input_directory).lexically_normal() !=
            fs::absolute(output_path).lexically_normal(),
            "Input and output paths must be different");
    auto package = make_temp_file(output_path);
    TemporaryPath cleanup(package);
    create_package(input_directory, package, progress);
    encrypt_file(package, output_path, credential, kDirectoryKind, bit_mode, progress);
}

void decrypt_file(const fs::path& input_path, const fs::path& output_path,
                  const Credential& credential, const Progress& progress) {
    require(fs::absolute(input_path).lexically_normal() !=
            fs::absolute(output_path).lexically_normal(),
            "Input and output paths must be different");
    require(!fs::exists(output_path), "Output already exists: " + output_path.string());
    auto temporary = make_temp_file(output_path);
    TemporaryPath cleanup(temporary);
    const auto kind = decrypt_file_to_temp(input_path, temporary, credential, progress);
    if (kind == kDirectoryKind) {
        extract_package(temporary, output_path, progress);
    } else {
        fs::rename(temporary, output_path);
        cleanup.release();
    }
}

Bytes seal_bytes(const Bytes& plaintext, const Credential& credential,
                 genetic_cipher::BitMode bit_mode) {
    const std::string raw(plaintext.begin(), plaintext.end());
    std::istringstream input(raw, std::ios::in | std::ios::binary);
    std::ostringstream output(std::ios::out | std::ios::binary);
    encrypt_stream(input, output, plaintext.size(), "text", credential, kFileKind,
                   bit_mode, {});
    const auto value = output.str();
    return Bytes(value.begin(), value.end());
}

Bytes open_bytes(const Bytes& ciphertext, const Credential& credential) {
    const std::string raw(ciphertext.begin(), ciphertext.end());
    std::istringstream input(raw, std::ios::in | std::ios::binary);
    std::ostringstream output(std::ios::out | std::ios::binary);
    const auto kind = decrypt_stream(input, output, ciphertext.size(), "text", credential, {});
    require(kind == kFileKind, "Encrypted input contains a directory package, not text");
    const auto value = output.str();
    return Bytes(value.begin(), value.end());
}

std::string base64_encode(const Bytes& input) {
    require(input.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
            "Text is too large for terminal mode");
    std::string output(4 * ((input.size() + 2) / 3), '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()),
                                     input.data(), static_cast<int>(input.size()));
    require(size >= 0, "Could not encode text output");
    output.resize(static_cast<std::size_t>(size));
    return output;
}

Bytes base64_decode(const std::string& input) {
    require(input.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
            input.size() % 4 == 0, "Invalid base64 text");
    Bytes output((input.size() / 4) * 3);
    const int size = EVP_DecodeBlock(output.data(),
                                     reinterpret_cast<const unsigned char*>(input.data()),
                                     static_cast<int>(input.size()));
    require(size >= 0, "Invalid base64 text");
    std::size_t actual = static_cast<std::size_t>(size);
    if (!input.empty() && input.back() == '=') --actual;
    if (input.size() > 1 && input[input.size() - 2] == '=') --actual;
    output.resize(actual);
    return output;
}

void print_help() {
    std::cout <<
        "stary - experimental genetic-cipher transformations\n\n"
        "Usage:\n"
        "  stary encrypt --input FILE --output FILE [credential options]\n"
        "  stary encrypt --directory DIR --output FILE [credential options]\n"
        "  stary decrypt --input FILE --output FILE_OR_NEW_DIRECTORY [credential options]\n"
        "  stary encrypt --text [credential options]\n"
        "  stary decrypt --text [credential options]\n\n"
        "Credential options: --password-file FILE or --key-file FILE, optionally with\n"
        "--electronic-password-file FILE. The electronic-password file uses its first line;\n"
        "spaces on that line are preserved. Encryption also accepts --bit-width BITS where\n"
        "BITS is 1, 2, 3, 4, 5, 6, 8, 16, 32, or 64. Width is stored in the envelope.\n"
        "Without a password or key file, stary prompts for a password without echo. Text\n"
        "mode reads one line from stdin; encryption prints base64 ciphertext.\n"
        "WARNING: this engine is experimental and unauthenticated; do not use it to protect\n"
        "sensitive data. Files are buffered in memory. See SECURITY.md for limitations.\n";
}

struct Options {
    std::string command;
    std::optional<fs::path> input;
    std::optional<fs::path> output;
    std::optional<fs::path> directory;
    std::optional<fs::path> password_file;
    std::optional<fs::path> key_file;
    std::optional<fs::path> electronic_password_file;
    std::optional<genetic_cipher::BitMode> bit_mode;
    bool text = false;
};

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::string {
            require(i + 1 < argc, "Missing value after " + arg);
            return argv[++i];
        };
        if (arg == "--help" || arg == "-h") {
            print_help();
            std::exit(0);
        } else if (arg == "--input") {
            options.input = value();
        } else if (arg == "--output") {
            options.output = value();
        } else if (arg == "--directory") {
            options.directory = value();
        } else if (arg == "--password-file") {
            options.password_file = value();
        } else if (arg == "--key-file") {
            options.key_file = value();
        } else if (arg == "--electronic-password-file") {
            options.electronic_password_file = value();
        } else if (arg == "--bit-width") {
            options.bit_mode = parse_bit_width(value());
        } else if (arg == "--text") {
            options.text = true;
        } else if (arg == "encrypt" || arg == "decrypt") {
            require(options.command.empty(), "Specify encrypt or decrypt only once");
            options.command = arg;
        } else {
            fail("Unknown argument: " + arg);
        }
    }
    return options;
}

Progress terminal_progress() {
    return [](const std::string& label, std::uint64_t done, std::uint64_t total) {
        const auto percent = total == 0 ? 100u : static_cast<unsigned>(
            std::min<std::uint64_t>(100, (done * 100) / total));
        std::cerr << '\r' << label << ": " << percent << "%" << std::flush;
        if (done >= total) std::cerr << '\n';
    };
}

int run(int argc, char** argv) {
    auto options = parse_options(argc, argv);
    require(options.command == "encrypt" || options.command == "decrypt",
            "Choose encrypt or decrypt (use --help for usage)");
    require(!(options.input && options.directory), "Use either --input or --directory, not both");
    require(!(options.text && (options.input || options.directory || options.output)),
            "--text cannot be combined with file or directory paths");
    require(!(options.directory && options.command != "encrypt"),
            "--directory is only valid for encryption");
    require(!(options.bit_mode && options.command != "encrypt"),
            "--bit-width is only valid for encryption");
    const auto bit_mode = options.bit_mode.value_or(genetic_cipher::BitMode::BYTE);
    std::cerr << "WARNING: genetic_cipher.hpp is experimental and unauthenticated; "
                 "do not use this output to protect sensitive data.\n";
    if (options.text) {
        std::string line;
        std::cout << (options.command == "encrypt" ? "Text to encrypt: " : "Base64 ciphertext: ")
                  << std::flush;
        require(static_cast<bool>(std::getline(std::cin, line)), "Could not read text input");
        auto credential = load_credential(options.password_file, options.key_file,
                                          options.electronic_password_file,
                                          options.command == "encrypt");
        if (options.command == "encrypt") {
            Bytes plain(line.begin(), line.end());
            std::cout << base64_encode(seal_bytes(plain, credential, bit_mode)) << '\n';
        } else {
            auto plain = open_bytes(base64_decode(line), credential);
            std::cout.write(reinterpret_cast<const char*>(plain.data()),
                            static_cast<std::streamsize>(plain.size()));
            std::cout << '\n';
        }
        return 0;
    }
    require(options.output.has_value(), "--output is required");
    require(options.input.has_value() || options.directory.has_value(),
            "--input or --directory is required");
    auto credential = load_credential(options.password_file, options.key_file,
                                      options.electronic_password_file,
                                      options.command == "encrypt");
    if (options.command == "encrypt") {
        if (options.directory)
            encrypt_directory(*options.directory, *options.output, credential, bit_mode,
                              terminal_progress());
        else
            encrypt_file(*options.input, *options.output, credential,
                         kFileKind, bit_mode, terminal_progress());
    } else {
        decrypt_file(*options.input, *options.output, credential, terminal_progress());
    }
    std::cout << "Done: " << options.output->string() << '\n';
    return 0;
}
} // namespace stary

#ifndef STARY_NO_MAIN
int main(int argc, char** argv) {
    try {
        return stary::run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "stary: " << error.what() << '\n';
        return 1;
    }
}
#endif
