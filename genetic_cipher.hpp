// genetic_cipher.hpp
// MIT License
// Copyright (c) 2026 Anthony Matarazzo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef GENETIC_CIPHER_HPP
#define GENETIC_CIPHER_HPP

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace genetic_cipher {

namespace fs = std::filesystem;

// Alignment-safe scalar read: casting an arbitrary byte pointer to uint64_t* is
// undefined behaviour on strict-alignment targets, so copy instead.
template<typename T>
inline T read_pod(const uint8_t*& p) {
    T value{};
    std::memcpy(&value, p, sizeof(T));
    p += sizeof(T);
    return value;
}

// ============================================================================
// Byte Span Aliases
// ============================================================================
using byte_span = std::span<uint8_t>;
using const_byte_span = std::span<const uint8_t>;

// Maximum number of file chunks pulled per streaming batch
constexpr size_t MAX_CONCURRENT_CHUNKS = 16;

// ============================================================================
// Version Information
// ============================================================================
constexpr uint32_t VERSION_MAJOR = 6;
constexpr uint32_t VERSION_MINOR = 1;
constexpr uint32_t VERSION_PATCH = 0;

// ============================================================================
// Bit Access Modes
// ============================================================================
enum class BitMode : uint8_t {
    BIT_1 = 1,
    BIT_2 = 2,
    BIT_3 = 3,
    NIBBLE = 4,
    BIT_5 = 5,
    BIT_6 = 6,
    BYTE = 8,
    WORD16 = 16,
    WORD32 = 32,
    WORD64 = 64,
    BLOCK = 128
};

constexpr size_t bit_mode_to_size(BitMode mode) {
    return static_cast<size_t>(mode);
}

constexpr size_t bits_to_bytes(size_t bits) {
    return (bits + 7) / 8;
}

// ============================================================================
// Distribution Parameters
// ============================================================================
struct DistributionParams {
    double coverage_percentage = 100.0;
    double subdivision_percentage = 100.0;
    size_t min_subdivision_size = 8;
    size_t max_subdivision_size = 1024;
    bool recursive_subdivisions = true;
    size_t recursion_depth = 3;
    
    DistributionParams() = default;
    DistributionParams(double coverage, double subdivision, bool recursive = true)
        : coverage_percentage(coverage), subdivision_percentage(subdivision), 
          recursive_subdivisions(recursive) {}
};

// ============================================================================
// File Access Mode
// ============================================================================
enum class FileAccessMode {
    SEQUENTIAL,     // Process files in order added
    INTERLEAVED,    // Round-robin chunk interleaving
    RANDOM_CHUNK,   // PRNG-determined random chunk order
    PRIORITY_BASED  // Larger files processed first
};

// ============================================================================
// Encryption Settings
// ============================================================================
struct EncryptionSettings {
    size_t window_size = 512;
    BitMode bit_mode = BitMode::BYTE;
    size_t parallel_threads = std::thread::hardware_concurrency();
    size_t chunk_size = 8192;
    size_t stream_buffer_size = 1024 * 1024;
    FileAccessMode file_access_mode = FileAccessMode::INTERLEAVED;
    size_t container_chunk_size = 4096;
    
    DistributionParams shape_distribution;
    bool enable_3d_shapes = true;
    bool enable_adaptive_shapes = true;
    
    double noise_level = 0.1;
    bool enable_adaptive_noise = true;
    bool enable_white_noise = true;
    bool enable_pink_noise = false;
    bool enable_brown_noise = false;
    bool enable_gaussian_noise = false;
    bool enable_impulse_noise = false;
    bool enable_quantum_noise = false;
    
    size_t scatter_passes = 3;
    size_t shuffle_passes = 2;
    size_t diffusion_rounds = 10;
    bool enable_rotation = true;
    bool enable_flip = true;
    
    bool preserve_timestamps = true;
    size_t read_buffer_size = 65536;
    bool enable_avalanche_boost = true;
    size_t key_derivation_rounds = 10000;
    bool delete_input_after_encryption = false;
    size_t minimum_encrypted_size = 4096;
    
    EncryptionSettings() {
        shape_distribution.coverage_percentage = 95.0;
        shape_distribution.subdivision_percentage = 80.0;
        shape_distribution.recursive_subdivisions = true;
        shape_distribution.recursion_depth = 3;
    }
};

// ============================================================================
// File Entry for Directory
// ============================================================================
struct FileEntry {
    std::string filename;
    std::string original_path;
    uint64_t original_size = 0;
    uint64_t encrypted_offset = 0;
    uint64_t encrypted_size = 0;
    uint64_t hash = 0;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> metadata;
    BitMode stored_bit_mode = BitMode::BYTE;
    FileAccessMode access_mode = FileAccessMode::SEQUENTIAL;
    uint64_t chunk_count = 0;
    std::vector<std::pair<uint64_t, uint64_t>> chunk_map;
    
    std::vector<uint8_t> serialize() const;
    static FileEntry deserialize(const_byte_span data);
};

// ============================================================================
// Directory Manager with Numeric Hash Integrity
// ============================================================================
class DirectoryManager {
private:
    std::unordered_map<std::string, FileEntry> m_files;
    mutable std::shared_mutex m_mutex;
    uint64_t m_total_size = 0;
    uint64_t m_directory_offset = 0;
    uint64_t m_directory_hash = 0;
    
    // Order-independent: an unordered_map's iteration order changes after a
    // deserialize, so hashing in iteration order made every archive fail its own
    // integrity check on load.
    uint64_t compute_directory_hash() const {
        std::vector<std::string> names;
        names.reserve(m_files.size());
        for (const auto& [name, entry] : m_files) names.push_back(name);
        std::sort(names.begin(), names.end());

        uint64_t hash = 0x9e3779b97f4a7c15ULL;
        for (const auto& name : names) {
            const auto& entry = m_files.at(name);
            for (char c : name) {
                hash = (hash ^ static_cast<uint64_t>(c)) * 0x9e3779b97f4a7c15ULL;
                hash = std::rotl(hash, 13);
            }
            hash = (hash ^ entry.original_size) * 0x9e3779b97f4a7c15ULL;
            hash = (hash ^ entry.encrypted_offset) * 0x9e3779b97f4a7c15ULL;
            hash = (hash ^ entry.hash) * 0x9e3779b97f4a7c15ULL;
            hash = std::rotl(hash, 17);
        }
        return hash;
    }
    
public:
    void add_file(const FileEntry& entry) {
        std::unique_lock lock(m_mutex);
        m_files[entry.filename] = entry;
        m_total_size += entry.original_size;
        m_directory_hash = compute_directory_hash();
    }
    
    void add_file(const std::string& filename, uint64_t size, uint64_t offset, 
                  uint64_t enc_size, uint64_t hash, BitMode mode, FileAccessMode access_mode) {
        std::unique_lock lock(m_mutex);
        FileEntry entry;
        entry.filename = fs::path(filename).filename().string();
        entry.original_path = filename;
        entry.original_size = size;
        entry.encrypted_offset = offset;
        entry.encrypted_size = enc_size;
        entry.hash = hash;
        entry.stored_bit_mode = mode;
        entry.access_mode = access_mode;
        entry.timestamp = std::chrono::system_clock::now();
        m_files[entry.filename] = entry;
        m_total_size += size;
        m_directory_hash = compute_directory_hash();
    }
    
    FileEntry get_file(const std::string& filename) const {
        std::shared_lock lock(m_mutex);
        auto it = m_files.find(filename);
        if (it != m_files.end()) return it->second;
        throw std::runtime_error("File not found: " + filename);
    }
    
    std::vector<std::string> list_files() const {
        std::shared_lock lock(m_mutex);
        std::vector<std::string> result;
        for (const auto& [name, entry] : m_files) result.push_back(name);
        return result;
    }
    
    std::vector<uint8_t> serialize() const {
        std::shared_lock lock(m_mutex);
        std::vector<uint8_t> data;
        
        uint64_t version = (static_cast<uint64_t>(VERSION_MAJOR) << 32) |
                           (static_cast<uint64_t>(VERSION_MINOR) << 16) |
                           static_cast<uint64_t>(VERSION_PATCH);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&version),
                   reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
        
        uint64_t file_count = static_cast<uint64_t>(m_files.size());
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&file_count),
                   reinterpret_cast<const uint8_t*>(&file_count) + sizeof(file_count));
        
        uint64_t dir_hash = m_directory_hash;
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&dir_hash),
                   reinterpret_cast<const uint8_t*>(&dir_hash) + sizeof(dir_hash));
        
        for (const auto& [name, entry] : m_files) {
            auto entry_data = entry.serialize();
            data.insert(data.end(), entry_data.begin(), entry_data.end());
        }
        
        return data;
    }
    
    bool deserialize_and_verify(const_byte_span data) {
        std::unique_lock lock(m_mutex);
        m_files.clear();
        m_total_size = 0;
        
        const uint8_t* ptr = data.data();
        
        uint64_t version = read_pod<uint64_t>(ptr);
        (void)version;   // format stamp, kept for forward compatibility checks
        
        uint64_t file_count = read_pod<uint64_t>(ptr);
        
        uint64_t expected_hash = read_pod<uint64_t>(ptr);
        
        for (uint64_t i = 0; i < file_count; ++i) {
            size_t max_size = data.size() - (ptr - data.data());
            std::vector<uint8_t> entry_data(ptr, ptr + max_size);
            FileEntry entry = FileEntry::deserialize(entry_data);
            size_t entry_size = entry.serialize().size();
            m_files[entry.filename] = entry;
            m_total_size += entry.original_size;
            ptr += entry_size;
        }
        
        uint64_t computed_hash = compute_directory_hash();
        if (computed_hash != expected_hash) {
            m_files.clear();
            m_total_size = 0;
            return false;
        }
        
        m_directory_hash = computed_hash;
        return true;
    }
    
    void deserialize(const_byte_span data) {
        if (!deserialize_and_verify(data)) {
            throw std::runtime_error("Directory integrity check failed - possible tampering");
        }
    }
    
    void update_chunk_map(const std::string& filename, uint64_t enc_offset, uint64_t orig_offset) {
        std::unique_lock lock(m_mutex);
        auto it = m_files.find(filename);
        if (it != m_files.end()) {
            it->second.chunk_map.emplace_back(enc_offset, orig_offset);
            it->second.chunk_count++;
            m_directory_hash = compute_directory_hash();
        }
    }
    
    void clear() {
        std::unique_lock lock(m_mutex);
        m_files.clear();
        m_total_size = 0;
        m_directory_hash = 0;
    }
    
    size_t file_count() const {
        std::shared_lock lock(m_mutex);
        return m_files.size();
    }
    
    uint64_t total_size() const {
        std::shared_lock lock(m_mutex);
        return m_total_size;
    }
    
    void set_directory_offset(uint64_t offset) { m_directory_offset = offset; }
    uint64_t directory_offset() const { return m_directory_offset; }
    uint64_t directory_hash() const { return m_directory_hash; }
    
    bool verify_integrity() const {
        std::shared_lock lock(m_mutex);
        return compute_directory_hash() == m_directory_hash;
    }
};

// ============================================================================
// FileEntry Implementation
// ============================================================================
inline std::vector<uint8_t> FileEntry::serialize() const {
    std::vector<uint8_t> data;
    
    uint32_t name_len = static_cast<uint32_t>(filename.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&name_len),
               reinterpret_cast<const uint8_t*>(&name_len) + sizeof(name_len));
    data.insert(data.end(), filename.begin(), filename.end());
    
    uint32_t path_len = static_cast<uint32_t>(original_path.length());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&path_len),
               reinterpret_cast<const uint8_t*>(&path_len) + sizeof(path_len));
    data.insert(data.end(), original_path.begin(), original_path.end());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&original_size),
               reinterpret_cast<const uint8_t*>(&original_size) + sizeof(original_size));
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&encrypted_offset),
               reinterpret_cast<const uint8_t*>(&encrypted_offset) + sizeof(encrypted_offset));
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&encrypted_size),
               reinterpret_cast<const uint8_t*>(&encrypted_size) + sizeof(encrypted_size));
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&hash),
               reinterpret_cast<const uint8_t*>(&hash) + sizeof(hash));
    
    uint8_t mode_byte = static_cast<uint8_t>(stored_bit_mode);
    data.push_back(mode_byte);
    
    uint8_t access_byte = static_cast<uint8_t>(access_mode);
    data.push_back(access_byte);
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&chunk_count),
               reinterpret_cast<const uint8_t*>(&chunk_count) + sizeof(chunk_count));
    
    uint32_t chunk_map_size = static_cast<uint32_t>(chunk_map.size());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&chunk_map_size),
               reinterpret_cast<const uint8_t*>(&chunk_map_size) + sizeof(chunk_map_size));
    
    for (const auto& [enc_off, orig_off] : chunk_map) {
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&enc_off),
                   reinterpret_cast<const uint8_t*>(&enc_off) + sizeof(enc_off));
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&orig_off),
                   reinterpret_cast<const uint8_t*>(&orig_off) + sizeof(orig_off));
    }
    
    auto time_val = timestamp.time_since_epoch().count();
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&time_val),
               reinterpret_cast<const uint8_t*>(&time_val) + sizeof(time_val));
    
    uint32_t meta_len = static_cast<uint32_t>(metadata.size());
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&meta_len),
               reinterpret_cast<const uint8_t*>(&meta_len) + sizeof(meta_len));
    data.insert(data.end(), metadata.begin(), metadata.end());
    
    return data;
}

inline FileEntry FileEntry::deserialize(const_byte_span data) {
    FileEntry entry;
    const uint8_t* ptr = data.data();
    
    uint32_t name_len = read_pod<uint32_t>(ptr);
    entry.filename = std::string(reinterpret_cast<const char*>(ptr), name_len);
    ptr += name_len;
    
    uint32_t path_len = read_pod<uint32_t>(ptr);
    entry.original_path = std::string(reinterpret_cast<const char*>(ptr), path_len);
    ptr += path_len;
    
    entry.original_size = read_pod<uint64_t>(ptr);
    entry.encrypted_offset = read_pod<uint64_t>(ptr);
    entry.encrypted_size = read_pod<uint64_t>(ptr);
    entry.hash = read_pod<uint64_t>(ptr);
    
    entry.stored_bit_mode = static_cast<BitMode>(*ptr);
    ptr += 1;
    
    entry.access_mode = static_cast<FileAccessMode>(*ptr);
    ptr += 1;
    
    entry.chunk_count = read_pod<uint64_t>(ptr);
    
    uint32_t chunk_map_size = read_pod<uint32_t>(ptr);
    
    for (uint32_t i = 0; i < chunk_map_size; ++i) {
        uint64_t enc_off = read_pod<uint64_t>(ptr);
        uint64_t orig_off = read_pod<uint64_t>(ptr);
        entry.chunk_map.emplace_back(enc_off, orig_off);
    }
    
    int64_t time_val = read_pod<int64_t>(ptr);
    entry.timestamp = std::chrono::system_clock::time_point(std::chrono::system_clock::duration(time_val));
    
    uint32_t meta_len = read_pod<uint32_t>(ptr);
    entry.metadata.assign(ptr, ptr + meta_len);
    
    return entry;
}

// ============================================================================
// High-Performance Container with Nodes and Tags
// ============================================================================
class container_t {
private:
    struct node_t {
        uint8_t* data;
        size_t size_bytes;
        size_t capacity_bytes;
        size_t element_count;
        BitMode mode;
        std::string tag;
        uint64_t node_id;
        std::atomic<node_t*> next;
        std::atomic<node_t*> prev;
        std::atomic<bool> reserved;
        
        node_t(size_t cap_bytes, uint64_t id, BitMode m = BitMode::BYTE, const std::string& t = "")
            : data(nullptr), size_bytes(0), capacity_bytes(cap_bytes), element_count(0), mode(m),
              tag(t), node_id(id), next(nullptr), prev(nullptr), reserved(false) {
            data = new uint8_t[capacity_bytes];
            std::memset(data, 0, capacity_bytes);
        }
        
        ~node_t() { delete[] data; }
        
        node_t(const node_t&) = delete;
        node_t& operator=(const node_t&) = delete;
    };
    
    std::atomic<node_t*> m_head;
    std::atomic<node_t*> m_tail;
    std::atomic<size_t> m_total_elements;
    std::atomic<size_t> m_total_bytes;
    std::atomic<size_t> m_node_count;
    std::atomic<uint64_t> m_next_node_id;
    BitMode m_global_mode;
    size_t m_bytes_per_element;
    mutable std::shared_mutex m_list_mutex;
    
    std::unordered_map<uint64_t, node_t*> m_node_map;
    mutable std::shared_mutex m_node_map_mutex;
    
    std::unordered_map<std::string, uint64_t> m_tag_to_node;
    mutable std::shared_mutex m_tag_mutex;
    
    // Bulk access window: operations read/write a flat element vector and pay the
    // locking and node lookup once per operation instead of once per element.
    std::vector<uint64_t> m_bulk;
    std::vector<uint64_t> m_bulk_masks;          // only used for mixed-width containers
    uint64_t m_bulk_uniform_mask = UINT64_MAX;   // fast path: every node has one width
    bool m_bulk_uniform = true;
    std::atomic<bool> m_bulk_active{false};

    struct PositionCache {
        uint64_t last_element;
        node_t* last_node;
        size_t last_node_start_element;
        PositionCache() : last_element(0), last_node(nullptr), last_node_start_element(0) {}
        void invalidate() { last_node = nullptr; }
    };
    mutable PositionCache m_position_cache;
    mutable std::shared_mutex m_cache_mutex;
    
    // Lock-free element access used inside a bulk window. Mirrors get_element /
    // set_element bit-for-bit (MSB-first) but skips locking and node lookup.
    static uint64_t read_element_raw(const node_t* node, size_t offset) {
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        size_t start_bit = offset * bits_per_elem;
        size_t start_byte = start_bit / 8;
        size_t bit_offset = start_bit % 8;
        uint64_t value = 0;
        for (size_t i = 0; i < bits_per_elem; ++i) {
            size_t byte_idx = start_byte + (bit_offset + i) / 8;
            size_t bit_in_byte = (bit_offset + i) % 8;
            if (byte_idx >= node->size_bytes) break;
            uint8_t bit = static_cast<uint8_t>((node->data[byte_idx] >> (7 - bit_in_byte)) & 1);
            value |= (static_cast<uint64_t>(bit) << (bits_per_elem - 1 - i));
        }
        return value;
    }

    static void write_element_raw(node_t* node, size_t offset, uint64_t value) {
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        uint64_t max_val = (bits_per_elem >= 64) ? UINT64_MAX : ((1ULL << bits_per_elem) - 1);
        value &= max_val;
        size_t start_bit = offset * bits_per_elem;
        size_t start_byte = start_bit / 8;
        size_t bit_offset = start_bit % 8;
        for (size_t i = 0; i < bits_per_elem; ++i) {
            size_t byte_idx = start_byte + (bit_offset + i) / 8;
            size_t bit_in_byte = (bit_offset + i) % 8;
            if (byte_idx >= node->size_bytes) break;
            uint8_t bit_value = static_cast<uint8_t>((value >> (bits_per_elem - 1 - i)) & 1);
            uint8_t mask = static_cast<uint8_t>(1u << (7 - bit_in_byte));
            if (bit_value) node->data[byte_idx] = static_cast<uint8_t>(node->data[byte_idx] | mask);
            else node->data[byte_idx] = static_cast<uint8_t>(node->data[byte_idx] & ~mask);
        }
    }

    void add_node_to_maps(node_t* node) {
        {
            std::unique_lock lock(m_node_map_mutex);
            m_node_map[node->node_id] = node;
        }
        if (!node->tag.empty()) {
            std::unique_lock lock(m_tag_mutex);
            m_tag_to_node[node->tag] = node->node_id;
        }
    }
    
    void remove_node_from_maps(node_t* node) {
        {
            std::unique_lock lock(m_node_map_mutex);
            m_node_map.erase(node->node_id);
        }
        if (!node->tag.empty()) {
            std::unique_lock lock(m_tag_mutex);
            m_tag_to_node.erase(node->tag);
        }
    }
    
    node_t* find_node_by_id(uint64_t id) const {
        std::shared_lock lock(m_node_map_mutex);
        auto it = m_node_map.find(id);
        return (it != m_node_map.end()) ? it->second : nullptr;
    }
    
    node_t* find_node_by_tag(const std::string& tag) const {
        std::shared_lock lock(m_tag_mutex);
        auto it = m_tag_to_node.find(tag);
        if (it == m_tag_to_node.end()) return nullptr;
        return find_node_by_id(it->second);
    }
    
    std::pair<node_t*, size_t> find_node_at_element(uint64_t absolute_element) const {
        {
            std::shared_lock cache_lock(m_cache_mutex);
            if (m_position_cache.last_node && 
                absolute_element >= m_position_cache.last_node_start_element &&
                absolute_element < m_position_cache.last_node_start_element + m_position_cache.last_node->element_count) {
                return {m_position_cache.last_node, 
                        absolute_element - m_position_cache.last_node_start_element};
            }
        }
        
        size_t current_element = 0;
        node_t* node = m_head.load();
        while (node) {
            if (absolute_element < current_element + node->element_count) {
                std::unique_lock cache_lock(m_cache_mutex);
                m_position_cache.last_element = absolute_element;
                m_position_cache.last_node = node;
                m_position_cache.last_node_start_element = current_element;
                return {node, absolute_element - current_element};
            }
            current_element += node->element_count;
            node = node->next.load();
        }
        return {nullptr, 0};
    }
    
    void invalidate_position_cache() {
        std::unique_lock lock(m_cache_mutex);
        m_position_cache.invalidate();
    }
    
    void pack_node_to_bytes(node_t* node) {
        if (!node) return;
        if (node->mode == BitMode::BYTE) return;
        
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        size_t required_bytes = bits_to_bytes(node->element_count * bits_per_elem);
        
        if (required_bytes > node->capacity_bytes) {
            size_t new_cap = std::max(required_bytes, node->capacity_bytes * 2);
            uint8_t* new_data = new uint8_t[new_cap];
            std::memset(new_data, 0, new_cap);
            
            for (size_t i = 0; i < node->element_count; ++i) {
                uint64_t value = 0;
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    size_t byte_idx = (start_bit + b) / 8;
                    size_t bit_in_byte = 7 - ((start_bit + b) % 8);
                    if (byte_idx < node->size_bytes && (node->data[byte_idx] & (1 << bit_in_byte))) {
                        value |= (1ULL << (bits_per_elem - 1 - b));
                    }
                }
                if (i < required_bytes) {
                    new_data[i] = static_cast<uint8_t>(value);
                }
            }
            delete[] node->data;
            node->data = new_data;
            node->size_bytes = required_bytes;
            node->capacity_bytes = new_cap;
        } else {
            std::vector<uint8_t> packed(required_bytes, 0);
            for (size_t i = 0; i < node->element_count; ++i) {
                uint64_t value = 0;
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    size_t byte_idx = (start_bit + b) / 8;
                    size_t bit_in_byte = 7 - ((start_bit + b) % 8);
                    if (byte_idx < node->size_bytes && (node->data[byte_idx] & (1 << bit_in_byte))) {
                        value |= (1ULL << (bits_per_elem - 1 - b));
                    }
                }
                if (i < packed.size()) {
                    packed[i] = static_cast<uint8_t>(value);
                }
            }
            std::memcpy(node->data, packed.data(), required_bytes);
            node->size_bytes = required_bytes;
        }
        node->mode = BitMode::BYTE;
    }
    
    void unpack_node_to_mode(node_t* node, BitMode target_mode) {
        if (!node) return;
        if (target_mode == BitMode::BYTE) return;
        
        size_t bits_per_elem = bit_mode_to_size(target_mode);
        size_t required_bytes = bits_to_bytes(node->element_count * bits_per_elem);
        
        if (required_bytes > node->capacity_bytes) {
            size_t new_cap = std::max(required_bytes, node->capacity_bytes * 2);
            uint8_t* new_data = new uint8_t[new_cap];
            std::memset(new_data, 0, new_cap);
            
            for (size_t i = 0; i < node->element_count; ++i) {
                uint8_t value = (i < node->size_bytes) ? node->data[i] : 0;
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    if (value & (1 << (bits_per_elem - 1 - b))) {
                        size_t bit_pos = start_bit + b;
                        size_t byte_idx = bit_pos / 8;
                        size_t bit_in_byte = 7 - (bit_pos % 8);
                        if (byte_idx < required_bytes) {
                            new_data[byte_idx] |= (1 << bit_in_byte);
                        }
                    }
                }
            }
            delete[] node->data;
            node->data = new_data;
            node->size_bytes = required_bytes;
            node->capacity_bytes = new_cap;
        } else {
            std::vector<uint8_t> unpacked(required_bytes, 0);
            for (size_t i = 0; i < node->element_count; ++i) {
                uint8_t value = (i < node->size_bytes) ? node->data[i] : 0;
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    if (value & (1 << (bits_per_elem - 1 - b))) {
                        size_t bit_pos = start_bit + b;
                        size_t byte_idx = bit_pos / 8;
                        size_t bit_in_byte = 7 - (bit_pos % 8);
                        if (byte_idx < unpacked.size()) {
                            unpacked[byte_idx] |= (1 << bit_in_byte);
                        }
                    }
                }
            }
            std::memcpy(node->data, unpacked.data(), required_bytes);
            node->size_bytes = required_bytes;
        }
        node->mode = target_mode;
    }
    
public:
    container_t(size_t chunk_size = 4096, BitMode mode = BitMode::BYTE)
        : m_head(nullptr), m_tail(nullptr), m_total_elements(0), m_total_bytes(0),
          m_node_count(0), m_next_node_id(0), m_global_mode(mode),
          m_bytes_per_element(bit_mode_to_size(mode) / 8) {
        (void)chunk_size;   // nodes grow on demand; kept for API compatibility
    }
    
    ~container_t() { clear(); }
    
    container_t(const container_t&) = delete;
    container_t& operator=(const container_t&) = delete;
    
    container_t(container_t&& other) noexcept
        : m_head(other.m_head.load()), m_tail(other.m_tail.load()),
          m_total_elements(other.m_total_elements.load()), m_total_bytes(other.m_total_bytes.load()),
          m_node_count(other.m_node_count.load()), m_next_node_id(other.m_next_node_id.load()),
          m_global_mode(other.m_global_mode), m_bytes_per_element(other.m_bytes_per_element) {
        {
            std::unique_lock lock(other.m_node_map_mutex);
            m_node_map = std::move(other.m_node_map);
            other.m_node_map.clear();
        }
        {
            std::unique_lock lock(other.m_tag_mutex);
            m_tag_to_node = std::move(other.m_tag_to_node);
            other.m_tag_to_node.clear();
        }
        other.m_head = nullptr; other.m_tail = nullptr;
        other.m_total_elements = 0; other.m_total_bytes = 0;
        other.m_node_count = 0;
    }
    
    container_t& operator=(container_t&& other) noexcept {
        if (this != &other) {
            clear();
            m_head = other.m_head.load(); m_tail = other.m_tail.load();
            m_total_elements = other.m_total_elements.load(); m_total_bytes = other.m_total_bytes.load();
            m_node_count = other.m_node_count.load(); m_next_node_id = other.m_next_node_id.load();
            m_global_mode = other.m_global_mode; m_bytes_per_element = other.m_bytes_per_element;
            {
                std::unique_lock lock(other.m_node_map_mutex);
                m_node_map = std::move(other.m_node_map);
                other.m_node_map.clear();
            }
            {
                std::unique_lock lock(other.m_tag_mutex);
                m_tag_to_node = std::move(other.m_tag_to_node);
                other.m_tag_to_node.clear();
            }
            other.m_head = nullptr; other.m_tail = nullptr;
            other.m_total_elements = 0; other.m_total_bytes = 0;
            other.m_node_count = 0;
        }
        return *this;
    }

    // Deep copy (copy construction / assignment are deleted for performance).
    // Snapshots the source under its lock, then rebuilds nodes with their
    // per-node bit modes, tags and element counts preserved.
    void copy_from(const container_t& other) {
        if (this == &other) return;

        struct node_snapshot {
            std::vector<uint8_t> bytes;
            BitMode mode;
            std::string tag;
            size_t element_count;
        };

        std::vector<node_snapshot> snap;
        {
            std::shared_lock lock(other.m_list_mutex);
            snap.reserve(other.m_node_count.load());
            for (node_t* src = other.m_head.load(); src != nullptr; src = src->next.load()) {
                node_snapshot s;
                s.bytes.assign(src->data, src->data + src->size_bytes);
                s.mode = src->mode;
                s.tag = src->tag;
                s.element_count = src->element_count;
                snap.push_back(std::move(s));
            }
        }

        const BitMode new_global_mode = other.m_global_mode;
        const size_t new_bytes_per_element = other.m_bytes_per_element;

        clear();
        m_global_mode = new_global_mode;
        m_bytes_per_element = new_bytes_per_element;

        std::unique_lock lock(m_list_mutex);
        for (auto& s : snap) {
            node_t* node = new node_t(std::max<size_t>(s.bytes.size(), m_bytes_per_element * 64),
                                      m_next_node_id++, s.mode, s.tag);
            if (!s.bytes.empty()) std::memcpy(node->data, s.bytes.data(), s.bytes.size());
            node->size_bytes = s.bytes.size();
            node->element_count = s.element_count;

            node_t* tail = m_tail.load();
            if (!tail) {
                m_head = node;
                m_tail = node;
            } else {
                tail->next = node;
                node->prev = tail;
                m_tail = node;
            }

            add_node_to_maps(node);
            m_total_elements.fetch_add(node->element_count);
            m_total_bytes.fetch_add(node->size_bytes);
            m_node_count.fetch_add(1);
        }
        invalidate_position_cache();
    }

    container_t clone() const {
        container_t copy(4096, m_global_mode);
        copy.copy_from(*this);
        return copy;
    }
    
    // ========================================================================
    // Element Access
    // ========================================================================
    
    // ---- bulk window -------------------------------------------------------
    void begin_bulk() {
        if (m_bulk_active.load(std::memory_order_relaxed)) return;
        std::shared_lock lock(m_list_mutex);
        m_bulk.clear();
        m_bulk_masks.clear();
        m_bulk.reserve(m_total_elements.load());

        // Single-width containers are the normal case; skip the per-element mask
        // array entirely for them.
        bool first = true;
        uint64_t uniform = UINT64_MAX;
        bool uniform_ok = true;
        for (node_t* node = m_head.load(); node != nullptr; node = node->next.load()) {
            size_t bits = bit_mode_to_size(node->mode);
            uint64_t mask = (bits >= 64) ? UINT64_MAX : ((1ULL << bits) - 1);
            if (first) { uniform = mask; first = false; }
            else if (mask != uniform) { uniform_ok = false; }
            for (size_t e = 0; e < node->element_count; ++e) {
                m_bulk.push_back(read_element_raw(node, e));
            }
        }
        m_bulk_uniform = uniform_ok;
        m_bulk_uniform_mask = uniform;
        if (!uniform_ok) {
            m_bulk_masks.reserve(m_bulk.size());
            for (node_t* node = m_head.load(); node != nullptr; node = node->next.load()) {
                size_t bits = bit_mode_to_size(node->mode);
                uint64_t mask = (bits >= 64) ? UINT64_MAX : ((1ULL << bits) - 1);
                for (size_t e = 0; e < node->element_count; ++e) m_bulk_masks.push_back(mask);
            }
        }
        m_bulk_active.store(true, std::memory_order_relaxed);
    }

    void end_bulk() {
        if (!m_bulk_active.exchange(false, std::memory_order_relaxed)) return;
        std::unique_lock lock(m_list_mutex);
        size_t idx = 0;
        for (node_t* node = m_head.load(); node != nullptr && idx < m_bulk.size();
             node = node->next.load()) {
            for (size_t e = 0; e < node->element_count && idx < m_bulk.size(); ++e, ++idx) {
                write_element_raw(node, e, m_bulk[idx]);
            }
        }
        invalidate_position_cache();
    }

    // Kept small so the common in-bulk call inlines to a compare and a load.
    uint64_t get_element(uint64_t element_index) const {
        if (m_bulk_active.load(std::memory_order_relaxed)) {
            return (element_index < m_bulk.size()) ? m_bulk[element_index] : 0;
        }
        return get_element_locked(element_index);
    }

    uint64_t get_element_locked(uint64_t element_index) const {
        std::shared_lock lock(m_list_mutex);
        auto [node, offset] = find_node_at_element(element_index);
        if (!node) return 0;
        
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        size_t start_bit = offset * bits_per_elem;
        size_t start_byte = start_bit / 8;
        size_t bit_offset = start_bit % 8;
        
        uint64_t value = 0;
        for (size_t i = 0; i < bits_per_elem; ++i) {
            size_t byte_idx = start_byte + (bit_offset + i) / 8;
            size_t bit_in_byte = (bit_offset + i) % 8;
            if (byte_idx >= node->size_bytes) break;
            uint8_t bit = (node->data[byte_idx] >> (7 - bit_in_byte)) & 1;
            value |= (static_cast<uint64_t>(bit) << (bits_per_elem - 1 - i));
        }
        return value;
    }
    
    void set_element(uint64_t element_index, uint64_t value) {
        if (m_bulk_active.load(std::memory_order_relaxed)) {
            if (element_index < m_bulk.size()) {
                m_bulk[element_index] = value & (m_bulk_uniform ? m_bulk_uniform_mask
                                                                : m_bulk_masks[element_index]);
            }
            return;
        }
        set_element_locked(element_index, value);
    }

    void set_element_locked(uint64_t element_index, uint64_t value) {
        std::unique_lock lock(m_list_mutex);
        auto [node, offset] = find_node_at_element(element_index);
        if (!node) return;
        
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        uint64_t max_val = (bits_per_elem >= 64) ? UINT64_MAX : ((1ULL << bits_per_elem) - 1);
        value &= max_val;
        
        size_t start_bit = offset * bits_per_elem;
        size_t start_byte = start_bit / 8;
        size_t bit_offset = start_bit % 8;
        
        for (size_t i = 0; i < bits_per_elem; ++i) {
            size_t byte_idx = start_byte + (bit_offset + i) / 8;
            size_t bit_in_byte = (bit_offset + i) % 8;
            
            if (byte_idx >= node->size_bytes) {
                size_t new_size = std::max(node->size_bytes, byte_idx + 1);
                if (new_size > node->capacity_bytes) {
                    size_t new_cap = std::max(new_size, node->capacity_bytes * 2);
                    uint8_t* new_data = new uint8_t[new_cap];
                    std::memcpy(new_data, node->data, node->size_bytes);
                    std::memset(new_data + node->size_bytes, 0, new_cap - node->size_bytes);
                    delete[] node->data;
                    node->data = new_data;
                    node->capacity_bytes = new_cap;
                }
                node->size_bytes = new_size;
            }
            
            uint8_t bit_value = (value >> (bits_per_elem - 1 - i)) & 1;
            uint8_t mask = (1u << (7 - bit_in_byte));
            if (bit_value) node->data[byte_idx] |= mask;
            else node->data[byte_idx] &= ~mask;
        }
        invalidate_position_cache();
    }
    
    uint8_t get_byte(size_t position) const {
        uint64_t element_idx = position / m_bytes_per_element;
        size_t byte_offset = position % m_bytes_per_element;
        uint64_t val = get_element(element_idx);
        return static_cast<uint8_t>((val >> (byte_offset * 8)) & 0xFF);
    }
    
    void set_byte(size_t position, uint8_t value) {
        uint64_t element_idx = position / m_bytes_per_element;
        size_t byte_offset = position % m_bytes_per_element;
        uint64_t current = get_element(element_idx);
        uint64_t mask = ~(static_cast<uint64_t>(0xFF) << (byte_offset * 8));
        uint64_t new_val = (current & mask) | (static_cast<uint64_t>(value) << (byte_offset * 8));
        set_element(element_idx, new_val);
    }
    
    // ========================================================================
    // Bulk Append Operations
    // ========================================================================
    
    void append_elements(const uint64_t* elements, size_t count, const std::string& tag = "") {
        if (!elements || count == 0) return;
        
        std::unique_lock lock(m_list_mutex);
        size_t bits_per_elem = bit_mode_to_size(m_global_mode);
        size_t bytes_needed = bits_to_bytes(count * bits_per_elem);
        
        node_t* node = new node_t(std::max(bytes_needed, m_bytes_per_element * 64), 
                                   m_next_node_id++, m_global_mode, tag);
        node->element_count = count;
        
        if (bits_per_elem >= 8) {
            // Most-significant byte first: get_element()/set_element() address bits
            // MSB-first, so a little-endian store here silently corrupted every
            // multi-byte mode (16/32/64-bit).
            size_t bytes_per_elem = bits_per_elem / 8;
            for (size_t i = 0; i < count; ++i) {
                for (size_t b = 0; b < bytes_per_elem; ++b) {
                    node->data[i * bytes_per_elem + b] =
                        static_cast<uint8_t>((elements[i] >> ((bytes_per_elem - 1 - b) * 8)) & 0xFF);
                }
            }
            node->size_bytes = count * bytes_per_elem;
        } else {
            std::vector<uint8_t> packed(bytes_needed, 0);
            for (size_t i = 0; i < count; ++i) {
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    if (elements[i] & (1ULL << (bits_per_elem - 1 - b))) {
                        size_t bit_pos = start_bit + b;
                        size_t byte_idx = bit_pos / 8;
                        size_t bit_in_byte = 7 - (bit_pos % 8);
                        if (byte_idx < packed.size()) {
                            packed[byte_idx] |= (1 << bit_in_byte);
                        }
                    }
                }
            }
            std::memcpy(node->data, packed.data(), bytes_needed);
            node->size_bytes = bytes_needed;
        }
        
        node_t* tail = m_tail.load();
        if (!tail) {
            m_head = node;
            m_tail = node;
        } else {
            tail->next = node;
            node->prev = tail;
            m_tail = node;
        }
        
        add_node_to_maps(node);
        m_total_elements.fetch_add(count);
        m_total_bytes.fetch_add(node->size_bytes);
        m_node_count.fetch_add(1);
        invalidate_position_cache();
    }
    
    void append_element(uint64_t element, const std::string& tag = "") {
        append_elements(&element, 1, tag);
    }
    
    void append_bytes(const uint8_t* bytes, size_t byte_count, const std::string& tag = "") {
        if (!bytes || byte_count == 0) return;
        
        std::unique_lock lock(m_list_mutex);
        node_t* node = new node_t(std::max(byte_count, m_bytes_per_element * 64), 
                                   m_next_node_id++, BitMode::BYTE, tag);
        node->element_count = byte_count;
        std::memcpy(node->data, bytes, byte_count);
        node->size_bytes = byte_count;
        node->mode = BitMode::BYTE;
        
        node_t* tail = m_tail.load();
        if (!tail) {
            m_head = node;
            m_tail = node;
        } else {
            tail->next = node;
            node->prev = tail;
            m_tail = node;
        }
        
        add_node_to_maps(node);
        m_total_elements.fetch_add(byte_count);
        m_total_bytes.fetch_add(byte_count);
        m_node_count.fetch_add(1);
        invalidate_position_cache();
    }
    
    // ========================================================================
    // Tag Management
    // ========================================================================
    
    void tag_node(const std::string& tag, uint64_t node_id) {
        node_t* node = find_node_by_id(node_id);
        if (node) {
            std::unique_lock lock(m_tag_mutex);
            if (!node->tag.empty()) {
                m_tag_to_node.erase(node->tag);
            }
            node->tag = tag;
            m_tag_to_node[tag] = node_id;
        }
    }
    
    void tag_current_node(const std::string& tag) {
        node_t* tail = m_tail.load();
        if (tail) {
            tag_node(tag, tail->node_id);
        }
    }
    
    node_t* get_node_by_tag(const std::string& tag) const {
        return find_node_by_tag(tag);
    }
    
    std::vector<uint64_t> read_tagged_chunk(const std::string& tag) const {
        node_t* node = find_node_by_tag(tag);
        if (!node) return {};
        
        std::vector<uint64_t> result(node->element_count);
        size_t bits_per_elem = bit_mode_to_size(node->mode);
        
        if (bits_per_elem >= 8) {
            size_t bytes_per_elem = bits_per_elem / 8;
            for (size_t i = 0; i < node->element_count; ++i) {
                uint64_t val = 0;
                for (size_t b = 0; b < bytes_per_elem; ++b) {
                    val |= static_cast<uint64_t>(node->data[i * bytes_per_elem + b]) << (b * 8);
                }
                result[i] = val;
            }
        } else {
            for (size_t i = 0; i < node->element_count; ++i) {
                uint64_t val = 0;
                size_t start_bit = i * bits_per_elem;
                for (size_t b = 0; b < bits_per_elem; ++b) {
                    size_t byte_idx = (start_bit + b) / 8;
                    size_t bit_in_byte = 7 - ((start_bit + b) % 8);
                    if (byte_idx < node->size_bytes && (node->data[byte_idx] & (1 << bit_in_byte))) {
                        val |= (1ULL << (bits_per_elem - 1 - b));
                    }
                }
                result[i] = val;
            }
        }
        return result;
    }
    
    // ========================================================================
    // Node Operations
    // ========================================================================
    
    void set_node_mode(uint64_t node_id, BitMode mode) {
        node_t* node = find_node_by_id(node_id);
        if (!node) return;
        if (node->mode == mode) return;
        
        std::unique_lock lock(m_list_mutex);
        if (mode == BitMode::BYTE) {
            pack_node_to_bytes(node);
        } else {
            unpack_node_to_mode(node, mode);
        }
    }
    
    void set_node_mode_by_tag(const std::string& tag, BitMode mode) {
        node_t* node = find_node_by_tag(tag);
        if (node) set_node_mode(node->node_id, mode);
    }
    
    void collapse_node(uint64_t node_id) {
        node_t* node = find_node_by_id(node_id);
        if (node && node->mode != BitMode::BYTE) {
            std::unique_lock lock(m_list_mutex);
            pack_node_to_bytes(node);
        }
    }
    
    void collapse_all() {
        std::unique_lock lock(m_list_mutex);
        node_t* node = m_head.load();
        while (node) {
            if (node->mode != BitMode::BYTE) {
                pack_node_to_bytes(node);
            }
            node = node->next.load();
        }
    }
    
    // ========================================================================
    // Utility Methods
    // ========================================================================
    
    size_t element_count() const { return m_total_elements.load(); }
    size_t total_bytes() const { return m_total_bytes.load(); }
    size_t node_count() const { return m_node_count.load(); }
    BitMode global_mode() const { return m_global_mode; }
    
    std::vector<uint8_t> to_bytes() const {
        std::shared_lock lock(m_list_mutex);
        std::vector<uint8_t> result;
        result.reserve(m_total_bytes.load());
        node_t* node = m_head.load();
        while (node) {
            result.insert(result.end(), node->data, node->data + node->size_bytes);
            node = node->next.load();
        }
        return result;
    }
    
    std::vector<uint64_t> to_elements() const {
        std::shared_lock lock(m_list_mutex);
        std::vector<uint64_t> result;
        result.reserve(m_total_elements.load());
        for (size_t i = 0; i < m_total_elements.load(); ++i) {
            result.push_back(get_element(i));
        }
        return result;
    }
    
    void clear() {
        std::unique_lock lock(m_list_mutex);
        node_t* curr = m_head.load();
        while (curr) {
            node_t* next = curr->next.load();
            delete curr;
            curr = next;
        }
        m_head = nullptr;
        m_tail = nullptr;
        m_total_elements = 0;
        m_total_bytes = 0;
        m_node_count = 0;
        m_next_node_id = 0;
        
        {
            std::unique_lock map_lock(m_node_map_mutex);
            m_node_map.clear();
        }
        {
            std::unique_lock tag_lock(m_tag_mutex);
            m_tag_to_node.clear();
        }
        invalidate_position_cache();
    }
    
    void resize(size_t new_byte_size) {
        size_t current = total_bytes();
        if (new_byte_size > current) {
            size_t needed_elements = (new_byte_size + m_bytes_per_element - 1) / m_bytes_per_element;
            size_t existing = element_count();
            if (needed_elements > existing) {
                std::vector<uint64_t> zeros(needed_elements - existing, 0);
                append_elements(zeros.data(), zeros.size());
            }
        }
    }
};

// ============================================================================
// Stealth Storage with Numeric Hash Integrity and Proper Insertion
// ============================================================================
class StealthStorage {
private:
    std::vector<uint8_t> m_integrity_hash;
    std::vector<uint8_t> m_stealth_data;
    std::vector<std::pair<size_t, size_t>> m_scatter_positions;
    bool m_is_verified;
    uint64_t m_stored_hash;
    
    uint64_t compute_numeric_hash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) const {
        uint64_t hash = 0x9e3779b97f4a7c15ULL;
        
        for (size_t i = 0; i < data.size(); ++i) {
            hash = (hash ^ data[i]) * 0x9e3779b97f4a7c15ULL;
            hash = std::rotl(hash, 13);
            if (i < key.size()) {
                hash ^= static_cast<uint64_t>(key[i]) << (i % 56);
            }
        }
        
        for (size_t i = 0; i < m_scatter_positions.size(); ++i) {
            hash = (hash ^ m_scatter_positions[i].first) * 0x9e3779b97f4a7c15ULL;
            hash = (hash ^ m_scatter_positions[i].second) * 0x9e3779b97f4a7c15ULL;
            hash = std::rotl(hash, 17);
        }
        
        return hash;
    }
    
public:
    StealthStorage() : m_is_verified(false), m_stored_hash(0) {}
    
    void generate_integrity_hash(const std::vector<uint8_t>& encryption_result,
                                   const std::vector<uint8_t>& key_material) {
        m_stored_hash = compute_numeric_hash(encryption_result, key_material);
        m_integrity_hash.resize(8);
        for (size_t i = 0; i < 8; ++i) {
            m_integrity_hash[i] = static_cast<uint8_t>((m_stored_hash >> (i * 8)) & 0xFF);
        }
    }
    
    bool verify_integrity(const std::vector<uint8_t>& encryption_result,
                          const std::vector<uint8_t>& key_material) {
        uint64_t computed = compute_numeric_hash(encryption_result, key_material);
        m_is_verified = (computed == m_stored_hash);
        return m_is_verified;
    }
    
    bool is_verified() const { return m_is_verified; }
    uint64_t stored_hash() const { return m_stored_hash; }
    
    void set_stealth_data(const std::vector<uint8_t>& data) { m_stealth_data = data; }
    void set_stored_hash(uint64_t hash) { m_stored_hash = hash; }
    void set_scatter_positions(const std::vector<std::pair<size_t, size_t>>& positions) { 
        m_scatter_positions = positions; 
    }
    
    void encrypt_stealth_data(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        m_stealth_data = data;
        for (size_t i = 0; i < m_stealth_data.size() && i < key.size(); ++i) {
            m_stealth_data[i] ^= key[i % key.size()];
            m_stealth_data[i] = std::rotl(m_stealth_data[i], (i % 7) + 1);
        }
    }
    
    std::vector<uint8_t> decrypt_stealth_data(const std::vector<uint8_t>& key) const {
        std::vector<uint8_t> result = m_stealth_data;
        for (size_t i = 0; i < result.size() && i < key.size(); ++i) {
            result[i] = std::rotr(result[i], (i % 7) + 1);
            result[i] ^= key[i % key.size()];
        }
        return result;
    }
    
    template<typename Container, typename PRNG>
    void blend_into_container(Container& container, const std::vector<uint8_t>& key, PRNG& prng) {
        if (m_stealth_data.empty()) return;
        
        size_t container_size = container.total_bytes();
        size_t stealth_size = m_stealth_data.size();
        
        if (container_size < stealth_size) {
            container.resize(stealth_size);
            container_size = stealth_size;
        }
        
        std::vector<uint8_t> encrypted_stealth = m_stealth_data;
        for (size_t i = 0; i < encrypted_stealth.size() && i < key.size(); ++i) {
            encrypted_stealth[i] ^= key[i % key.size()];
            encrypted_stealth[i] = std::rotl(encrypted_stealth[i], (i % 7) + 1);
        }
        
        m_scatter_positions.clear();
        size_t num_chunks = std::max(size_t(1), stealth_size / 256);
        size_t chunk_size = stealth_size / num_chunks;
        
        for (size_t i = 0; i < num_chunks; ++i) {
            size_t pos = prng.generate_range_u64(0, container_size - chunk_size);
            size_t len = (i == num_chunks - 1) ? stealth_size - (chunk_size * (num_chunks - 1)) : chunk_size;
            m_scatter_positions.emplace_back(pos, len);
            
            size_t data_offset = i * chunk_size;
            for (size_t j = 0; j < len && data_offset + j < encrypted_stealth.size(); ++j) {
                if (pos + j < container_size) {
                    uint8_t existing = container.get_byte(pos + j);
                    container.set_byte(pos + j, existing ^ encrypted_stealth[data_offset + j]);
                } else {
                    container.set_byte(pos + j, encrypted_stealth[data_offset + j]);
                }
            }
        }
    }
    
    template<typename Container>
    std::vector<uint8_t> extract_from_container(Container& container) {
        std::vector<uint8_t> result;
        for (const auto& [pos, len] : m_scatter_positions) {
            for (size_t i = 0; i < len && pos + i < container.total_bytes(); ++i) {
                result.push_back(container.get_byte(pos + i));
            }
        }
        
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] = std::rotr(result[i], (i % 7) + 1);
        }
        
        return result;
    }
    
    template<typename Container>
    void remove_from_container(Container& container) {
        for (const auto& [pos, len] : m_scatter_positions) {
            for (size_t i = 0; i < len && pos + i < container.total_bytes(); ++i) {
                container.set_byte(pos + i, 0);
            }
        }
    }
    
    const std::vector<uint8_t>& integrity_hash() const { return m_integrity_hash; }
    const std::vector<std::pair<size_t, size_t>>& scatter_positions() const { return m_scatter_positions; }
    const std::vector<uint8_t>& stealth_data() const { return m_stealth_data; }
};

// ============================================================================
// Bidirectional Cryptographically Secure PRNG
// ============================================================================
class CryptographicPRNG {
private:
    std::array<uint64_t, 16> m_state;
    std::vector<uint64_t> m_cache_forward;
    std::vector<uint64_t> m_cache_backward;
    size_t m_cache_index;
    uint64_t m_counter;
    uint64_t m_initial_counter;
    int64_t m_direction;
    std::array<uint8_t, 32> m_key;
    std::array<uint8_t, 12> m_nonce;
    std::array<uint8_t, 32> m_base_key{};
    std::array<uint8_t, 12> m_base_nonce{};
    mutable std::mutex m_mutex;
    std::vector<uint8_t> m_electronic_password_buffer;
    size_t m_ep_position;
    bool m_is_seeded;
    
    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = std::rotl(d, 16);
        c += d; b ^= c; b = std::rotl(b, 12);
        a += b; d ^= a; d = std::rotl(d, 8);
        c += d; b ^= c; b = std::rotl(b, 7);
    }
    
    void generate_block_forward() {
        std::array<uint32_t, 16> working_state;
        for (int i = 0; i < 16; ++i) {
            working_state[i] = static_cast<uint32_t>(m_state[i] & 0xFFFFFFFF);
        }
        
        for (int round = 0; round < 10; ++round) {
            quarter_round(working_state[0], working_state[4], working_state[8], working_state[12]);
            quarter_round(working_state[1], working_state[5], working_state[9], working_state[13]);
            quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
            quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);
            quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
            quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
            quarter_round(working_state[2], working_state[7], working_state[8], working_state[13]);
            quarter_round(working_state[3], working_state[4], working_state[9], working_state[14]);
        }
        
        m_cache_forward.clear();
        for (int i = 0; i < 16; ++i) {
            uint64_t val = static_cast<uint64_t>(working_state[i]);
            val += m_state[i];
            m_cache_forward.push_back(val);
        }
        m_counter++;
        m_state[12] = m_counter & 0xFFFFFFFF;
        m_state[13] = (m_counter >> 32) & 0xFFFFFFFF;
    }
    
    void generate_block_backward() {
        if (m_counter > m_initial_counter) {
            m_counter--;
            m_state[12] = m_counter & 0xFFFFFFFF;
            m_state[13] = (m_counter >> 32) & 0xFFFFFFFF;
            
            std::array<uint32_t, 16> working_state;
            for (int i = 0; i < 16; ++i) {
                working_state[i] = static_cast<uint32_t>(m_state[i] & 0xFFFFFFFF);
            }
            
            for (int round = 0; round < 10; ++round) {
                quarter_round(working_state[0], working_state[4], working_state[8], working_state[12]);
                quarter_round(working_state[1], working_state[5], working_state[9], working_state[13]);
                quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
                quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);
                quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
                quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
                quarter_round(working_state[2], working_state[7], working_state[8], working_state[13]);
                quarter_round(working_state[3], working_state[4], working_state[9], working_state[14]);
            }
            
            m_cache_backward.clear();
            for (int i = 0; i < 16; ++i) {
                uint64_t val = static_cast<uint64_t>(working_state[i]);
                val += m_state[i];
                m_cache_backward.push_back(val);
            }
        }
    }
    
    void init_state() {
        m_state[0] = 0x61707865;
        m_state[1] = 0x3320646e;
        m_state[2] = 0x79622d32;
        m_state[3] = 0x6b206574;
        
        for (int i = 0; i < 8; ++i) {
            m_state[4 + i] = (static_cast<uint64_t>(m_key[i * 4]) |
                             (static_cast<uint64_t>(m_key[i * 4 + 1]) << 8) |
                             (static_cast<uint64_t>(m_key[i * 4 + 2]) << 16) |
                             (static_cast<uint64_t>(m_key[i * 4 + 3]) << 24));
        }
        
        m_state[12] = m_counter & 0xFFFFFFFF;
        m_state[13] = (m_counter >> 32) & 0xFFFFFFFF;
        m_state[14] = (static_cast<uint64_t>(m_nonce[0]) |
                      (static_cast<uint64_t>(m_nonce[1]) << 8) |
                      (static_cast<uint64_t>(m_nonce[2]) << 16) |
                      (static_cast<uint64_t>(m_nonce[3]) << 24));
        m_state[15] = (static_cast<uint64_t>(m_nonce[4]) |
                      (static_cast<uint64_t>(m_nonce[5]) << 8) |
                      (static_cast<uint64_t>(m_nonce[6]) << 16) |
                      (static_cast<uint64_t>(m_nonce[7]) << 24));
    }
    
    void advance_electronic_password() {
        if (m_electronic_password_buffer.empty()) return;
        m_ep_position = (m_ep_position + 1) % m_electronic_password_buffer.size();
        
        if (m_ep_position % 256 == 0) {
            for (size_t i = 0; i < 8 && i < m_electronic_password_buffer.size(); ++i) {
                m_state[i] ^= static_cast<uint64_t>(m_electronic_password_buffer[m_ep_position]) << ((i % 8) * 8);
            }
            init_state();
        }
    }
    
public:
    CryptographicPRNG() : m_cache_index(0), m_counter(0), m_initial_counter(0), 
                          m_direction(1), m_ep_position(0), m_is_seeded(false) {
        m_state.fill(0);
        m_key.fill(0);
        m_nonce.fill(0);
        m_cache_forward.reserve(16);
        m_cache_backward.reserve(16);
    }
    
    void seed(const_byte_span user_password, const_byte_span electronic_password) {
        std::unique_lock lock(m_mutex);
        
        m_electronic_password_buffer.assign(electronic_password.begin(), electronic_password.end());
        m_ep_position = 0;
        
        std::array<uint8_t, 32> key_material;
        key_material.fill(0);
        
        for (size_t i = 0; i < user_password.size(); ++i) {
            key_material[i % 32] ^= user_password[i];
            key_material[(i + 7) % 32] += user_password[i];
            key_material[(i + 13) % 32] = std::rotl(key_material[(i + 13) % 32], 3) ^ user_password[i];
        }
        
        for (size_t i = 0; i < electronic_password.size(); ++i) {
            key_material[i % 32] ^= electronic_password[i];
            key_material[(i + 11) % 32] -= electronic_password[i];
            key_material[(i + 19) % 32] = std::rotr(key_material[(i + 19) % 32], 5) ^ electronic_password[i];
        }
        
        for (int round = 0; round < 10; ++round) {
            for (size_t i = 0; i < 32; ++i) {
                key_material[i] ^= key_material[(i + 1) % 32];
                key_material[i] = std::rotl(key_material[i], 3);
                key_material[i] += key_material[(i + 15) % 32];
            }
        }
        
        std::copy(key_material.begin(), key_material.end(), m_key.begin());
        for (size_t i = 0; i < 12; ++i) {
            m_nonce[i] = key_material[i] ^ key_material[i + 20];
        }
        m_base_key = m_key;
        m_base_nonce = m_nonce;
        
        m_counter = 0;
        m_initial_counter = 0;
        m_direction = 1;
        init_state();
        generate_block_forward();
        m_is_seeded = true;
    }
    
    // Re-derive the whole generator from the stored key material plus a token.
    // Called before every operation so encryption and decryption see the exact
    // same keystream without having to replay the generator backwards.
    void reseed(uint64_t token) {
        std::unique_lock lock(m_mutex);

        std::array<uint8_t, 32> km = m_base_key;
        uint8_t token_bytes[8];
        std::memcpy(token_bytes, &token, sizeof(token_bytes));
        for (size_t i = 0; i < 32; ++i) {
            km[i] ^= token_bytes[i % 8];
            km[i] = std::rotl(km[i], 3);
            km[i] = static_cast<uint8_t>(km[i] + ((i * 31u + 7u) & 0xFF));
            km[i] ^= km[(i + 13) % 32];
        }
        for (int round = 0; round < 4; ++round) {
            for (size_t i = 0; i < 32; ++i) {
                km[i] ^= km[(i + 1) % 32];
                km[i] = std::rotl(km[i], 5);
                km[i] = static_cast<uint8_t>(km[i] + km[(i + 11) % 32]);
            }
        }

        std::copy(km.begin(), km.end(), m_key.begin());
        for (size_t i = 0; i < 12; ++i) m_nonce[i] = static_cast<uint8_t>(km[i] ^ km[i + 20]);

        m_counter = 0;
        m_initial_counter = 0;
        m_direction = 1;
        m_cache_index = 0;
        m_cache_forward.clear();
        m_cache_backward.clear();
        m_ep_position = 0;
        init_state();
        generate_block_forward();
        m_is_seeded = true;
    }

    void set_direction_forward() {
        std::unique_lock lock(m_mutex);
        if (m_direction == -1) {
            m_counter = m_initial_counter;
            init_state();
            m_cache_index = 0;
            m_cache_forward.clear();
            generate_block_forward();
        }
        m_direction = 1;
    }
    
    void set_direction_backward() {
        std::unique_lock lock(m_mutex);
        if (m_direction == 1) {
            m_initial_counter = m_counter;
            m_direction = -1;
        }
        m_cache_index = 0;
    }
    
    uint64_t generate_u64() {
        std::unique_lock lock(m_mutex);
        if (!m_is_seeded) return 0;
        
        if (m_direction == 1) {
            if (m_cache_index >= m_cache_forward.size()) {
                generate_block_forward();
                m_cache_index = 0;   // refilled cache starts over; index must follow
            }
            advance_electronic_password();
            return m_cache_forward[m_cache_index++];
        } else {
            if (m_cache_index >= m_cache_backward.size()) {
                generate_block_backward();
                m_cache_index = 0;   // refilled cache starts over
                if (m_cache_backward.empty()) return 0;
            }
            advance_electronic_password();
            return m_cache_backward[m_cache_index++];
        }
    }
    
    uint32_t generate_u32() { return static_cast<uint32_t>(generate_u64() & 0xFFFFFFFF); }
    uint16_t generate_u16() { return static_cast<uint16_t>(generate_u64() & 0xFFFF); }
    uint8_t generate_u8() { return static_cast<uint8_t>(generate_u64() & 0xFF); }
    
    uint64_t generate_range_u64(uint64_t min, uint64_t max) {
        uint64_t range = max - min + 1;
        uint64_t limit = UINT64_MAX - (UINT64_MAX % range);
        uint64_t value;
        do { value = generate_u64(); } while (value >= limit);
        return min + (value % range);
    }
    
    int64_t generate_range_i64(int64_t min, int64_t max) {
        return static_cast<int64_t>(generate_range_u64(static_cast<uint64_t>(min), static_cast<uint64_t>(max)));
    }
    
    double generate_double() { return static_cast<double>(generate_u64()) / static_cast<double>(UINT64_MAX); }
    double generate_range_double(double min, double max) { return min + generate_double() * (max - min); }
    bool generate_bool(double probability = 0.5) { return generate_double() < probability; }
    
    void generate_bytes(byte_span output) {
        for (size_t i = 0; i < output.size(); i += 8) {
            uint64_t value = generate_u64();
            size_t remaining = std::min<size_t>(8, output.size() - i);
            std::memcpy(output.data() + i, &value, remaining);
        }
    }
    
    std::vector<uint8_t> generate_bytes(size_t count) {
        std::vector<uint8_t> result(count);
        generate_bytes(result);
        return result;
    }
    
    std::vector<size_t> generate_permutation(size_t size) {
        std::vector<size_t> permutation(size);
        std::iota(permutation.begin(), permutation.end(), 0);
        for (size_t i = size - 1; i > 0; --i) {
            size_t j = generate_range_u64(0, i);
            std::swap(permutation[i], permutation[j]);
        }
        return permutation;
    }
    
    double generate_gaussian(double mean = 0.0, double stddev = 1.0) {
        double u1 = generate_double(), u2 = generate_double();
        return mean + stddev * std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
    }
    
    void reset_for_decryption() {
        std::unique_lock lock(m_mutex);
        m_counter = m_initial_counter;
        m_direction = -1;
        m_cache_index = 0;
        m_cache_backward.clear();
        init_state();
    }
};

// ============================================================================
// Grid2D Class for Shape Operations
// ============================================================================
class Grid2D {
private:
    size_t m_width, m_height, m_total_elements;
    
public:
    Grid2D(size_t total_elements) {
        m_width = static_cast<size_t>(std::sqrt(total_elements));
        m_height = m_width;
        while (m_width * m_height > total_elements) m_height--;
        m_total_elements = m_width * m_height;
    }
    
    size_t width() const { return m_width; }
    size_t height() const { return m_height; }
    size_t total() const { return m_total_elements; }
    size_t index(size_t x, size_t y) const { return (x < m_width && y < m_height) ? y * m_width + x : SIZE_MAX; }
    bool is_valid(size_t x, size_t y) const { return x < m_width && y < m_height; }
    
    void swap_elements(container_t& data, size_t i1, size_t i2) const {
        uint64_t v1 = data.get_element(i1);
        uint64_t v2 = data.get_element(i2);
        data.set_element(i1, v2);
        data.set_element(i2, v1);
    }
    
    void swap_rows(size_t row1, size_t row2, container_t& data) const {
        if (row1 >= m_height || row2 >= m_height) return;
        for (size_t x = 0; x < m_width; ++x) {
            swap_elements(data, index(x, row1), index(x, row2));
        }
    }
    
    void swap_columns(size_t col1, size_t col2, container_t& data) const {
        if (col1 >= m_width || col2 >= m_width) return;
        for (size_t y = 0; y < m_height; ++y) {
            swap_elements(data, index(col1, y), index(col2, y));
        }
    }
    
    std::vector<size_t> get_row(size_t row) const {
        std::vector<size_t> result;
        if (row < m_height) {
            for (size_t x = 0; x < m_width; ++x) {
                result.push_back(index(x, row));
            }
        }
        return result;
    }
    
    std::vector<size_t> get_column(size_t col) const {
        std::vector<size_t> result;
        if (col < m_width) {
            for (size_t y = 0; y < m_height; ++y) {
                result.push_back(index(col, y));
            }
        }
        return result;
    }
};

// ============================================================================
// Shape Transform Base Class
// ============================================================================
struct ShapeContext {
    CryptographicPRNG& prng;
    const DistributionParams& params;
    size_t total_elements;
    BitMode bit_mode;
    size_t current_round;
    
    ShapeContext(CryptographicPRNG& p, const DistributionParams& par, size_t total, BitMode mode)
        : prng(p), params(par), total_elements(total), bit_mode(mode), current_round(0) {}
};

class ShapeTransform {
protected:
    DistributionParams m_params;
public:
    explicit ShapeTransform(const DistributionParams& params = DistributionParams()) : m_params(params) {}
    virtual ~ShapeTransform() = default;
    virtual void transform(container_t& data, ShapeContext& ctx) = 0;
    virtual void inverse_transform(container_t& data, ShapeContext& ctx) = 0;
    virtual std::string name() const = 0;
};

// ============================================================================
// Built-in Shape Transforms
// ============================================================================
class SquareTransform : public ShapeTransform {
public:
    explicit SquareTransform(const DistributionParams& params = DistributionParams()) : ShapeTransform(params) {}
    // Row/column swaps are involutions, but the sequence is not: it is replayed in
    // reverse order on the way back.
    void collect_ops(ShapeContext& ctx, std::vector<std::pair<int, std::pair<size_t, size_t>>>& ops) {
        size_t side = static_cast<size_t>(std::sqrt(ctx.total_elements));
        if (side < 2) return;
        size_t count = static_cast<size_t>(side * ctx.params.subdivision_percentage / 100.0);
        count = std::max(count, size_t(2));
        for (size_t op = 0; op < count; ++op) {
            int type = static_cast<int>(ctx.prng.generate_range_i64(0, 1));
            size_t a = ctx.prng.generate_range_u64(0, side - 1);
            size_t b = ctx.prng.generate_range_u64(0, side - 1);
            if (a != b) ops.push_back({type, {a, b}});
        }
    }
    void apply_ops(container_t& data, ShapeContext& ctx,
                   const std::vector<std::pair<int, std::pair<size_t, size_t>>>& ops, bool reverse) {
        Grid2D grid(ctx.total_elements);
        auto run = [&](const std::pair<int, std::pair<size_t, size_t>>& op) {
            if (op.first == 0) grid.swap_rows(op.second.first, op.second.second, data);
            else grid.swap_columns(op.second.first, op.second.second, data);
        };
        if (reverse) {
            for (size_t i = ops.size(); i-- > 0;) run(ops[i]);
        } else {
            for (const auto& op : ops) run(op);
        }
    }
    void transform(container_t& data, ShapeContext& ctx) override {
        std::vector<std::pair<int, std::pair<size_t, size_t>>> ops;
        collect_ops(ctx, ops);
        apply_ops(data, ctx, ops, false);
    }
    void inverse_transform(container_t& data, ShapeContext& ctx) override {
        std::vector<std::pair<int, std::pair<size_t, size_t>>> ops;
        collect_ops(ctx, ops);
        apply_ops(data, ctx, ops, true);
    }
    std::string name() const override { return "SquareTransform"; }
};

class CircleTransform : public ShapeTransform {
public:
    explicit CircleTransform(const DistributionParams& params = DistributionParams()) : ShapeTransform(params) {}
    void rings(ShapeContext& ctx, std::vector<std::vector<size_t>>& out) {
        size_t side = static_cast<size_t>(std::sqrt(ctx.total_elements));
        if (side < 4) return;
        Grid2D grid(ctx.total_elements);
        size_t radius_count = static_cast<size_t>(side / 2 * ctx.params.subdivision_percentage / 100.0);
        radius_count = std::max(radius_count, size_t(2));
        for (size_t r = 1; r <= radius_count; ++r) {
            std::vector<size_t> indices;
            for (int angle = 0; angle < 360; angle += 10) {
                double rad = angle * M_PI / 180.0;
                int x = static_cast<int>(side / 2 + static_cast<double>(r) * std::cos(rad));
                int y = static_cast<int>(side / 2 + static_cast<double>(r) * std::sin(rad));
                if (grid.is_valid(x, y)) indices.push_back(grid.index(x, y));
            }
            std::sort(indices.begin(), indices.end());
            indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
            if (indices.size() > 1) out.push_back(std::move(indices));
        }
    }

    void rotate_rings(container_t& data, ShapeContext& ctx, bool inverse) {
        std::vector<std::vector<size_t>> ring_list;
        rings(ctx, ring_list);
        for (auto& indices : ring_list) {
            size_t len = indices.size();
            int64_t shift = ctx.prng.generate_range_i64(1, static_cast<int64_t>(len) - 1);
            if (ctx.prng.generate_bool(0.5)) shift = -shift;
            if (inverse) shift = -shift;
            std::vector<uint64_t> values;
            values.reserve(len);
            for (size_t idx : indices) values.push_back(data.get_element(idx));
            for (size_t i = 0; i < len; ++i) {
                size_t new_idx = indices[(i + shift + static_cast<int64_t>(len)) % static_cast<int64_t>(len)];
                data.set_element(new_idx, values[i]);
            }
        }
    }

    void transform(container_t& data, ShapeContext& ctx) override { rotate_rings(data, ctx, false); }
    void inverse_transform(container_t& data, ShapeContext& ctx) override { rotate_rings(data, ctx, true); }
    std::string name() const override { return "CircleTransform"; }
};

// ============================================================================
// Operation Tag Structs - All Fully Reversible
// ============================================================================
struct Scatter {};
struct Shuffle {};
struct Diffuse {};
struct Mix {};
struct Permute {};
struct Rotate {};
struct Flip {};
struct Swap {};

struct BitwiseNot {};
struct BitwiseRotL {};
struct BitwiseRotR {};
struct BitwiseReverse {};
struct BitwiseSwapNibbles {};
struct BitwiseGrayCode {};
struct BitwiseXor {};
struct BitwiseAnd {};
struct BitwiseOr {};

struct ArithmeticNegate {};
struct ArithmeticAdd {};
struct ArithmeticSub {};
struct ArithmeticMul {};
struct ArithmeticDiv {};

struct ByteSwap {};
struct ByteReverse {};
struct ByteRotate {};
struct WordSwap {};
struct WordMix {};

struct TransformXorShift {};
struct TransformChaCha {};
struct TransformAES {};

struct PushMode {};
struct PopMode {};
struct SwitchMode {};
struct ModeCycle {};
struct ModeFeedback {};

struct ChunkPermute {};
struct ChunkCascade {};

struct Cascade {};
struct Spiral {};
struct Interleave {};
struct Entangle {};
struct Avalanche {};
struct FractalPermute {};
struct ChaosInject {};

struct BufferMixer {};
struct DualBlockWeave {};
struct InstructionCascade {};
struct StateMachineMix {};
struct LoopFusion {};
struct BlockResonance {};

struct ParallelScatter {};
struct ParallelShuffle {};
struct ParallelDiffuse {};

struct NoiseWhite {};
struct NoisePink {};
struct NoiseBrown {};
struct NoiseGaussian {};
struct NoiseImpulse {};
struct NoiseQuantum {};
struct NoiseAdaptive {};
struct NoiseStructured {};
struct NoiseChaotic {};

// ============================================================================
// File Chunk for Streaming
// ============================================================================
struct FileChunk {
    std::string filename;
    uint64_t file_offset;
    uint64_t chunk_size;
    uint64_t original_offset;
    uint64_t chunk_id;
    std::vector<uint8_t> data;
    bool is_complete;
    uint64_t priority;
    
    FileChunk() : file_offset(0), chunk_size(0), original_offset(0), 
                  chunk_id(0), is_complete(false), priority(0) {}
};

// ============================================================================
// Main Genetic Cipher Class with Full Streaming Support
// ============================================================================
template<typename... Operations>
class GeneticCipher {
private:
    CryptographicPRNG m_prng;
    EncryptionSettings m_settings;
    container_t m_data;
    std::vector<uint8_t> m_user_password;
    std::vector<uint8_t> m_electronic_password;
    std::vector<std::unique_ptr<ShapeTransform>> m_custom_transforms;
    std::vector<BitMode> m_mode_stack;
    StealthStorage m_stealth;
    DirectoryManager m_directory;
    
    // Streaming file management
    struct PendingFileInfo {
        std::string filename;
        std::string original_path;
        uint64_t file_size;
        uint64_t bytes_processed;
        uint64_t total_chunks;
        uint64_t file_hash;
        FileAccessMode access_mode;
        std::vector<uint64_t> chunk_offsets;  // For RANDOM_CHUNK mode
        size_t next_chunk_index;
        
        PendingFileInfo() : file_size(0), bytes_processed(0), total_chunks(0),
                            file_hash(0), access_mode(FileAccessMode::SEQUENTIAL),
                            next_chunk_index(0) {}
    };
    
    std::unordered_map<std::string, PendingFileInfo> m_pending_files;
    uint64_t m_current_encrypted_offset;
    std::ofstream m_output_stream;
    std::string m_current_output_file;
    mutable std::mutex m_encrypt_mutex;
    
    BitMode current_mode() const {
        return m_mode_stack.empty() ? m_settings.bit_mode : m_mode_stack.back();
    }
    
    // ============================================================================
    // Streaming File Chunk Retrieval Methods
    // ============================================================================
    
    std::vector<FileChunk> get_next_chunks_sequential() {
        std::vector<FileChunk> chunks;
        static uint64_t global_chunk_id = 0;
        
        for (auto& [filename, info] : m_pending_files) {
            if (info.bytes_processed < info.file_size && chunks.size() < MAX_CONCURRENT_CHUNKS) {
                FileChunk chunk;
                chunk.filename = info.filename;
                chunk.file_offset = info.bytes_processed;
                chunk.chunk_size = std::min(m_settings.chunk_size, info.file_size - info.bytes_processed);
                chunk.original_offset = info.bytes_processed;
                chunk.chunk_id = global_chunk_id++;
                chunk.is_complete = (info.bytes_processed + chunk.chunk_size >= info.file_size);
                chunk.priority = 1;
                
                // Read chunk data from file
                std::ifstream file(info.original_path, std::ios::binary);
                if (file.is_open()) {
                    file.seekg(chunk.file_offset);
                    chunk.data.resize(chunk.chunk_size);
                    file.read(reinterpret_cast<char*>(chunk.data.data()), chunk.chunk_size);
                    file.close();
                }
                
                info.bytes_processed += chunk.chunk_size;
                chunks.push_back(std::move(chunk));
            }
        }
        return chunks;
    }
    
    std::vector<FileChunk> get_next_chunks_interleaved() {
        std::vector<FileChunk> chunks;
        static uint64_t global_chunk_id = 0;
        static size_t current_file_index = 0;
        
        std::vector<std::string> active_files;
        for (const auto& [filename, info] : m_pending_files) {
            if (info.bytes_processed < info.file_size) {
                active_files.push_back(filename);
            }
        }
        
        if (active_files.empty()) return chunks;
        
        for (size_t i = 0; i < std::min(MAX_CONCURRENT_CHUNKS, active_files.size()); ++i) {
            const auto& filename = active_files[(current_file_index + i) % active_files.size()];
            auto& info = m_pending_files[filename];
            
            if (info.bytes_processed < info.file_size) {
                FileChunk chunk;
                chunk.filename = info.filename;
                chunk.file_offset = info.bytes_processed;
                chunk.chunk_size = std::min(m_settings.chunk_size, info.file_size - info.bytes_processed);
                chunk.original_offset = info.bytes_processed;
                chunk.chunk_id = global_chunk_id++;
                chunk.is_complete = (info.bytes_processed + chunk.chunk_size >= info.file_size);
                chunk.priority = 1;
                
                std::ifstream file(info.original_path, std::ios::binary);
                if (file.is_open()) {
                    file.seekg(chunk.file_offset);
                    chunk.data.resize(chunk.chunk_size);
                    file.read(reinterpret_cast<char*>(chunk.data.data()), chunk.chunk_size);
                    file.close();
                }
                
                info.bytes_processed += chunk.chunk_size;
                chunks.push_back(std::move(chunk));
            }
        }
        
        current_file_index = (current_file_index + 1) % active_files.size();
        return chunks;
    }
    
    std::vector<FileChunk> get_next_chunks_random() {
        std::vector<FileChunk> chunks;
        static uint64_t global_chunk_id = 0;
        
        for (auto& [filename, info] : m_pending_files) {
            if (info.next_chunk_index < info.total_chunks && chunks.size() < MAX_CONCURRENT_CHUNKS) {
                if (info.chunk_offsets.empty()) {
                    // Generate random chunk order using PRNG
                    info.total_chunks = (info.file_size + m_settings.chunk_size - 1) / m_settings.chunk_size;
                    info.chunk_offsets.resize(info.total_chunks);
                    for (uint64_t i = 0; i < info.total_chunks; ++i) {
                        info.chunk_offsets[i] = i * m_settings.chunk_size;
                    }
                    // Fisher-Yates shuffle using PRNG
                    for (uint64_t i = info.total_chunks - 1; i > 0; --i) {
                        uint64_t j = m_prng.generate_range_u64(0, i);
                        std::swap(info.chunk_offsets[i], info.chunk_offsets[j]);
                    }
                }
                
                FileChunk chunk;
                chunk.filename = info.filename;
                chunk.file_offset = info.chunk_offsets[info.next_chunk_index];
                chunk.chunk_size = std::min(m_settings.chunk_size, info.file_size - chunk.file_offset);
                chunk.original_offset = chunk.file_offset;
                chunk.chunk_id = global_chunk_id++;
                chunk.is_complete = (info.next_chunk_index + 1 >= info.total_chunks);
                chunk.priority = m_prng.generate_range_u64(1, 100);
                
                std::ifstream file(info.original_path, std::ios::binary);
                if (file.is_open()) {
                    file.seekg(chunk.file_offset);
                    chunk.data.resize(chunk.chunk_size);
                    file.read(reinterpret_cast<char*>(chunk.data.data()), chunk.chunk_size);
                    file.close();
                }
                
                info.next_chunk_index++;
                chunks.push_back(std::move(chunk));
            }
        }
        return chunks;
    }
    
    std::vector<FileChunk> get_next_chunks_priority() {
        std::vector<FileChunk> chunks;
        static uint64_t global_chunk_id = 0;
        
        // Build priority queue based on remaining file size (largest first)
        using PriorityPair = std::pair<uint64_t, std::string>;
        std::priority_queue<PriorityPair> priority_queue;
        
        for (const auto& [filename, info] : m_pending_files) {
            if (info.bytes_processed < info.file_size) {
                uint64_t remaining = info.file_size - info.bytes_processed;
                priority_queue.emplace(remaining, filename);
            }
        }
        
        while (!priority_queue.empty() && chunks.size() < MAX_CONCURRENT_CHUNKS) {
            auto [priority, filename] = priority_queue.top();
            priority_queue.pop();
            
            auto& info = m_pending_files[filename];
            if (info.bytes_processed < info.file_size) {
                FileChunk chunk;
                chunk.filename = info.filename;
                chunk.file_offset = info.bytes_processed;
                chunk.chunk_size = std::min(m_settings.chunk_size, info.file_size - info.bytes_processed);
                chunk.original_offset = info.bytes_processed;
                chunk.chunk_id = global_chunk_id++;
                chunk.is_complete = (info.bytes_processed + chunk.chunk_size >= info.file_size);
                chunk.priority = priority;
                
                std::ifstream file(info.original_path, std::ios::binary);
                if (file.is_open()) {
                    file.seekg(chunk.file_offset);
                    chunk.data.resize(chunk.chunk_size);
                    file.read(reinterpret_cast<char*>(chunk.data.data()), chunk.chunk_size);
                    file.close();
                }
                
                info.bytes_processed += chunk.chunk_size;
                chunks.push_back(std::move(chunk));
            }
        }
        
        return chunks;
    }
    
    // ============================================================================
    // Reversible Operation Core
    // ============================================================================
    //
    // Design rule: every operation must be a bijection on the element vector for
    // a given keystream. Before each operation - during encryption and during
    // decryption alike - the PRNG is reseeded with a token derived from that
    // operation's position in the Operations pack (see run_forward/run_inverse).
    // Forward and inverse therefore see identical randomness, so an inverse only
    // has to undo the maths and never has to rewind the stream.
    // ============================================================================

    static uint64_t element_mask(size_t bits) {
        return (bits >= 64) ? ~uint64_t(0) : ((uint64_t(1) << bits) - 1);
    }

    // Multiplicative inverse modulo 2^64 for odd a (Newton iteration, doubles bits).
    static uint64_t mod_inverse_odd(uint64_t a) {
        uint64_t x = a;
        for (int i = 0; i < 6; ++i) x *= 2 - a * x;
        return x;
    }

    // Rotations must stay inside the element width: a 64-bit std::rotl followed by
    // masking silently discards bits for narrow modes (1/2/3/4/5/6/8/16/32).
    static uint64_t rotl_within(uint64_t v, unsigned r, size_t bits) {
        if (bits == 0) return v;
        r %= static_cast<unsigned>(bits);
        if (r == 0) return v;
        uint64_t mask = element_mask(bits);
        v &= mask;
        return ((v << r) | (v >> (bits - r))) & mask;
    }

    static uint64_t rotr_within(uint64_t v, unsigned r, size_t bits) {
        if (bits == 0) return v;
        r %= static_cast<unsigned>(bits);
        if (r == 0) return v;
        uint64_t mask = element_mask(bits);
        v &= mask;
        return ((v >> r) | (v << (bits - r))) & mask;
    }

    static uint64_t mix64(uint64_t z) {
        z += 0x9E3779B97F4A7C15ULL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    // Inverse of y = x ^ (x << k), rebuilt from the low bits upward.
    static uint64_t undo_xorshift_left(uint64_t y, unsigned k) {
        uint64_t x = 0;
        for (unsigned i = 0; i < 64; ++i) {
            uint64_t prev = (i >= k) ? ((x >> (i - k)) & 1ULL) : 0ULL;
            if (((y >> i) & 1ULL) ^ prev) x |= (1ULL << i);
        }
        return x;
    }

    // Inverse of y = x ^ (x >> k), rebuilt from the high bits downward.
    static uint64_t undo_xorshift_right(uint64_t y, unsigned k) {
        uint64_t x = 0;
        for (int i = 63; i >= 0; --i) {
            uint64_t next = (i + static_cast<int>(k) < 64) ? ((x >> (i + k)) & 1ULL) : 0ULL;
            if (((y >> i) & 1ULL) ^ next) x |= (1ULL << i);
        }
        return x;
    }

    // Inverse of y = x + (x >> k): strictly increasing, solved by contraction.
    static uint64_t undo_add_shift_right(uint64_t y, unsigned k) {
        uint64_t x = y;
        for (int i = 0; i < 80; ++i) x = y - (x >> k);
        return x;
    }

    // ---------------------------------------------------------------------------
    // Permutation helpers
    // ---------------------------------------------------------------------------

    // out[perm[i]] = in[i]
    void perm_apply(container_t& d, const std::vector<uint64_t>& perm) {
        size_t n = perm.size();
        std::vector<uint64_t> vals(n);
        for (size_t i = 0; i < n; ++i) vals[perm[i]] = d.get_element(i);
        for (size_t i = 0; i < n; ++i) d.set_element(i, vals[i]);
    }

    // in[i] = out[perm[i]]
    void perm_unapply(container_t& d, const std::vector<uint64_t>& perm) {
        size_t n = perm.size();
        std::vector<uint64_t> vals(n);
        for (size_t i = 0; i < n; ++i) vals[i] = d.get_element(perm[i]);
        for (size_t i = 0; i < n; ++i) d.set_element(i, vals[i]);
    }

    std::vector<uint64_t> fisher_yates(size_t n) {
        std::vector<uint64_t> perm(n);
        for (size_t i = 0; i < n; ++i) perm[i] = static_cast<uint64_t>(i);
        for (size_t i = n; i-- > 1;) {
            size_t j = m_prng.generate_range_u64(0, i);
            std::swap(perm[i], perm[j]);
        }
        return perm;
    }

    // ---------------------------------------------------------------------------
    // AES substitution tables, generated so both directions are exact inverses
    // ---------------------------------------------------------------------------

    static uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) p ^= a;
            uint8_t hi = static_cast<uint8_t>(a & 0x80);
            a = static_cast<uint8_t>(a << 1);
            if (hi) a ^= 0x1B;
            b = static_cast<uint8_t>(b >> 1);
        }
        return p;
    }

    static uint8_t gf_pow(uint8_t a, uint8_t e) {
        uint8_t r = 1;
        while (e) {
            if (e & 1) r = gf_mul(r, a);
            a = gf_mul(a, a);
            e = static_cast<uint8_t>(e >> 1);
        }
        return r;
    }

    static const std::array<uint8_t, 256>& aes_sbox() {
        static const std::array<uint8_t, 256> box = []() {
            std::array<uint8_t, 256> s{};
            for (int i = 0; i < 256; ++i) {
                uint8_t inv = (i == 0) ? uint8_t(0) : gf_pow(static_cast<uint8_t>(i), 254);
                uint8_t y = 0x63;
                for (int b = 0; b < 5; ++b) {
                    uint8_t rot = static_cast<uint8_t>(((inv << b) | (inv >> (8 - b))) & 0xFF);
                    y ^= rot;
                }
                s[i] = y;
            }
            return s;
        }();
        return box;
    }

    static const std::array<uint8_t, 256>& aes_inv_sbox() {
        static const std::array<uint8_t, 256> inv = []() {
            std::array<uint8_t, 256> r{};
            const auto& s = aes_sbox();
            for (int i = 0; i < 256; ++i) r[s[i]] = static_cast<uint8_t>(i);
            return r;
        }();
        return inv;
    }

    // ============================================================================
    // Positional Operations
    // ============================================================================

    void apply_scatter(container_t& data) {
        for (size_t pass = 0; pass < m_settings.scatter_passes; ++pass) {
            size_t n = data.element_count();
            if (n < 2) return;
            perm_apply(data, m_prng.generate_permutation(n));
        }
    }

    void unapply_scatter(container_t& data) {
        std::vector<std::vector<uint64_t>> perms;
        for (size_t pass = 0; pass < m_settings.scatter_passes; ++pass) {
            size_t n = data.element_count();
            if (n < 2) return;
            perms.push_back(m_prng.generate_permutation(n));
        }
        for (size_t k = perms.size(); k-- > 0;) perm_unapply(data, perms[k]);
    }

    void apply_shuffle(container_t& data) {
        for (size_t pass = 0; pass < m_settings.shuffle_passes; ++pass) {
            size_t n = data.element_count();
            if (n < 2) return;
            perm_apply(data, fisher_yates(n));
        }
    }

    void unapply_shuffle(container_t& data) {
        std::vector<std::vector<uint64_t>> perms;
        for (size_t pass = 0; pass < m_settings.shuffle_passes; ++pass) {
            size_t n = data.element_count();
            if (n < 2) return;
            perms.push_back(fisher_yates(n));
        }
        for (size_t k = perms.size(); k-- > 0;) perm_unapply(data, perms[k]);
    }

    // Cumulative chain in both directions: one changed element reaches every other
    // element within a single round. The previous one-step neighbour XOR diffused a
    // single position per round, which is why a one-bit change barely spread.
    void apply_diffuse(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t round = 0; round < m_settings.diffusion_rounds; ++round) {
            for (size_t i = 1; i < n; ++i) {
                data.set_element(i, data.get_element(i) ^ data.get_element(i - 1));
            }
            for (size_t i = n - 1; i-- > 0;) {
                data.set_element(i, data.get_element(i) ^ data.get_element(i + 1));
            }
        }
    }

    void unapply_diffuse(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t round = m_settings.diffusion_rounds; round-- > 0;) {
            for (size_t i = 0; i + 1 < n; ++i) {
                data.set_element(i, data.get_element(i) ^ data.get_element(i + 1));
            }
            for (size_t i = n; i-- > 1;) {
                data.set_element(i, data.get_element(i) ^ data.get_element(i - 1));
            }
        }
    }

    void apply_mix(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, data.get_element(i) ^ m_prng.generate_u64());
        }
    }

    void apply_permute(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        size_t block = std::max<size_t>(2, n / 16);
        for (size_t b = 0; b < n; b += block) {
            size_t len = std::min(block, n - b);
            if (len < 2) continue;
            auto perm = fisher_yates(len);
            std::vector<uint64_t> vals(len);
            for (size_t i = 0; i < len; ++i) vals[perm[i]] = data.get_element(b + i);
            for (size_t i = 0; i < len; ++i) data.set_element(b + i, vals[i]);
        }
    }

    void unapply_permute(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        size_t block = std::max<size_t>(2, n / 16);
        for (size_t b = 0; b < n; b += block) {
            size_t len = std::min(block, n - b);
            if (len < 2) continue;
            auto perm = fisher_yates(len);
            std::vector<uint64_t> vals(len);
            for (size_t i = 0; i < len; ++i) vals[i] = data.get_element(b + perm[i]);
            for (size_t i = 0; i < len; ++i) data.set_element(b + i, vals[i]);
        }
    }

    void apply_rotate(container_t& data) {
        if (!m_settings.enable_rotation) return;
        size_t n = data.element_count();
        if (n < 2) return;
        size_t shift = m_prng.generate_range_u64(1, n - 1);
        std::vector<uint64_t> values(n);
        for (size_t i = 0; i < n; ++i) values[(i + shift) % n] = data.get_element(i);
        for (size_t i = 0; i < n; ++i) data.set_element(i, values[i]);
    }

    void unapply_rotate(container_t& data) {
        if (!m_settings.enable_rotation) return;
        size_t n = data.element_count();
        if (n < 2) return;
        size_t shift = m_prng.generate_range_u64(1, n - 1);
        size_t inv_shift = (n - shift) % n;
        std::vector<uint64_t> values(n);
        for (size_t i = 0; i < n; ++i) values[(i + inv_shift) % n] = data.get_element(i);
        for (size_t i = 0; i < n; ++i) data.set_element(i, values[i]);
    }

    void apply_flip(container_t& data) {
        if (!m_settings.enable_flip) return;
        size_t n = data.element_count();
        for (size_t i = 0; i < n / 2; ++i) {
            size_t j = n - 1 - i;
            uint64_t vi = data.get_element(i);
            uint64_t vj = data.get_element(j);
            data.set_element(i, vj);
            data.set_element(j, vi);
        }
    }

    void apply_swap(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        size_t block_size = std::max<size_t>(1, n / 8);
        for (size_t i = 0; i + block_size * 2 <= n; i += block_size * 2) {
            for (size_t j = 0; j < block_size; ++j) {
                size_t a = i + j, b = i + block_size + j;
                uint64_t va = data.get_element(a);
                uint64_t vb = data.get_element(b);
                data.set_element(a, vb);
                data.set_element(b, va);
            }
        }
    }

    // ============================================================================
    // Bitwise Operations
    // ============================================================================

    void apply_bitwise_not(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, ~data.get_element(i));
        }
    }

    void apply_bitwise_rotl(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 2) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            unsigned rot = static_cast<unsigned>(m_prng.generate_range_u64(1, bits - 1));
            data.set_element(i, rotl_within(data.get_element(i), rot, bits));
        }
    }

    void apply_bitwise_rotr(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 2) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            unsigned rot = static_cast<unsigned>(m_prng.generate_range_u64(1, bits - 1));
            data.set_element(i, rotr_within(data.get_element(i), rot, bits));
        }
    }

    void apply_bitwise_reverse(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t rev = 0;
            for (size_t b = 0; b < bits; ++b) {
                if (val & (1ULL << b)) rev |= (1ULL << (bits - 1 - b));
            }
            data.set_element(i, rev);
        }
    }

    void apply_bitwise_swap_nibbles(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 2) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            if (bits >= 8) {
                val = ((val & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((val & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
            } else {
                // Rotating by half the width is only an involution for even widths,
                // so narrow modes get an explicit inverse below.
                val = rotl_within(val, static_cast<unsigned>(bits / 2), bits);
            }
            data.set_element(i, val);
        }
    }

    void unapply_bitwise_swap_nibbles(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 2) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            if (bits >= 8) {
                val = ((val & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((val & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
            } else {
                val = rotr_within(val, static_cast<unsigned>(bits / 2), bits);
            }
            data.set_element(i, val);
        }
    }

    void apply_bitwise_gray_code(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            data.set_element(i, val ^ (val >> 1));
        }
    }

    void unapply_bitwise_gray_code(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t x = data.get_element(i);
            for (size_t s = 1; s < bits; s <<= 1) x ^= (x >> s);
            data.set_element(i, x);
        }
    }

    void apply_bitwise_xor(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, data.get_element(i) ^ m_prng.generate_u64());
        }
    }

    // Invertible bit-mixing stand-in for AND (multiplication by an odd constant is
    // a bijection modulo 2^bits).
    void apply_bitwise_and(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = (m_prng.generate_u64() | 1ULL) & mask;
            if (k == 0) k = 1;
            data.set_element(i, (data.get_element(i) * k) & mask);
        }
    }

    void unapply_bitwise_and(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = (m_prng.generate_u64() | 1ULL) & mask;
            if (k == 0) k = 1;
            data.set_element(i, (data.get_element(i) * mod_inverse_odd(k)) & mask);
        }
    }

    // Invertible bit-mixing stand-in for OR (position-rotated keystream XOR).
    void apply_bitwise_or(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 1) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            unsigned rot = static_cast<unsigned>(i % bits);
            uint64_t k = std::rotl(m_prng.generate_u64(), static_cast<int>(rot));
            data.set_element(i, data.get_element(i) ^ k);
        }
    }

    // ============================================================================
    // Arithmetic Operations (modulo 2^bits, odd multipliers keep them invertible)
    // ============================================================================

    void apply_arithmetic_negate(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, static_cast<uint64_t>(0) - data.get_element(i));
        }
    }

    void apply_arithmetic_add(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, data.get_element(i) + m_prng.generate_range_u64(1, 255));
        }
    }

    void apply_arithmetic_sub(container_t& data) {
        for (size_t i = 0; i < data.element_count(); ++i) {
            data.set_element(i, data.get_element(i) - m_prng.generate_range_u64(1, 255));
        }
    }

    void apply_arithmetic_mul(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = m_prng.generate_range_u64(1, 255) | 1ULL;
            data.set_element(i, (data.get_element(i) * k) & mask);
        }
    }

    void unapply_arithmetic_mul(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = m_prng.generate_range_u64(1, 255) | 1ULL;
            data.set_element(i, (data.get_element(i) * mod_inverse_odd(k)) & mask);
        }
    }

    void apply_arithmetic_div(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = m_prng.generate_range_u64(1, 255) | 1ULL;
            data.set_element(i, (data.get_element(i) * mod_inverse_odd(k)) & mask);
        }
    }

    void unapply_arithmetic_div(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t k = m_prng.generate_range_u64(1, 255) | 1ULL;
            data.set_element(i, (data.get_element(i) * k) & mask);
        }
    }

    // ============================================================================
    // Byte / Word Operations
    // ============================================================================

    void apply_byte_swap(container_t& data) {
        size_t bytes = bit_mode_to_size(data.global_mode()) / 8;
        if (bytes < 2) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t swapped = 0;
            for (size_t b = 0; b < bytes; ++b) {
                uint8_t byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFF);
                swapped |= static_cast<uint64_t>(byte_val) << ((bytes - 1 - b) * 8);
            }
            data.set_element(i, swapped);
        }
    }

    void apply_byte_reverse(container_t& data) {
        if (bit_mode_to_size(data.global_mode()) < 8) return;
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t rev = 0;
            for (int b = 0; b < 8; ++b) {
                uint8_t byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFF);
                uint8_t rev_byte = 0;
                for (int bit = 0; bit < 8; ++bit) {
                    if (byte_val & (1 << bit)) rev_byte = static_cast<uint8_t>(rev_byte | (1 << (7 - bit)));
                }
                rev |= static_cast<uint64_t>(rev_byte) << (b * 8);
            }
            data.set_element(i, rev);
        }
    }

    void apply_byte_rotate(container_t& data) {
        size_t bytes = bit_mode_to_size(data.global_mode()) / 8;
        if (bytes < 2) return;
        unsigned rot = static_cast<unsigned>(m_prng.generate_range_u64(1, bytes - 1));
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t rotated = 0;
            for (size_t b = 0; b < bytes; ++b) {
                size_t src = (b + bytes - rot) % bytes;
                uint8_t byte_val = static_cast<uint8_t>((val >> (src * 8)) & 0xFF);
                rotated |= static_cast<uint64_t>(byte_val) << (b * 8);
            }
            data.set_element(i, rotated);
        }
    }

    void unapply_byte_rotate(container_t& data) {
        size_t bytes = bit_mode_to_size(data.global_mode()) / 8;
        if (bytes < 2) return;
        unsigned rot = static_cast<unsigned>(m_prng.generate_range_u64(1, bytes - 1));
        unsigned inv_rot = static_cast<unsigned>((bytes - rot) % bytes);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t rotated = 0;
            for (size_t b = 0; b < bytes; ++b) {
                size_t src = (b + bytes - inv_rot) % bytes;
                uint8_t byte_val = static_cast<uint8_t>((val >> (src * 8)) & 0xFF);
                rotated |= static_cast<uint64_t>(byte_val) << (b * 8);
            }
            data.set_element(i, rotated);
        }
    }

    void apply_word_swap(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 32) return;
        size_t half = bits / 2;
        uint64_t hmask = element_mask(half);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t low = val & hmask;
            uint64_t high = (val >> half) & hmask;
            data.set_element(i, (low << half) | high);
        }
    }

    void apply_word_mix(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 32) return;
        size_t half = bits / 2;
        uint64_t hmask = element_mask(half);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t low = val & hmask;
            uint64_t high = (val >> half) & hmask;
            uint64_t mixed_low = (low ^ high) & hmask;
            uint64_t mixed_high = (high ^ ((mixed_low << 1) & hmask)) & hmask;
            data.set_element(i, (mixed_high << half) | mixed_low);
        }
    }

    void unapply_word_mix(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        if (bits < 32) return;
        size_t half = bits / 2;
        uint64_t hmask = element_mask(half);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t mixed_low = val & hmask;
            uint64_t mixed_high = (val >> half) & hmask;
            uint64_t high = (mixed_high ^ ((mixed_low << 1) & hmask)) & hmask;
            uint64_t low = (mixed_low ^ high) & hmask;
            data.set_element(i, (high << half) | low);
        }
    }

    // ============================================================================
    // Transform Operations
    // ============================================================================

    // Intermediate values are masked to the element width: a 64-bit mix truncated
    // on write would destroy bits that the inverse needs to recover.
    void apply_transform_xorshift(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i) & mask;
            val = (val ^ (val << 13)) & mask;
            val = (val ^ (val >> 7)) & mask;
            val = (val ^ (val << 17)) & mask;
            data.set_element(i, val);
        }
    }

    void unapply_transform_xorshift(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t mask = element_mask(bits);
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i) & mask;
            val = undo_xorshift_left(val, 17) & mask;
            val = undo_xorshift_right(val, 7) & mask;
            val = undo_xorshift_left(val, 13) & mask;
            data.set_element(i, val);
        }
    }

    void apply_transform_chacha(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i + 3 < data.element_count(); i += 4) {
            uint64_t a = data.get_element(i);
            uint64_t b = data.get_element(i + 1);
            uint64_t c = data.get_element(i + 2);
            uint64_t d = data.get_element(i + 3);
            uint64_t m = element_mask(bits);
            a = (a + b) & m; d = (d ^ a) & m; d = rotl_within(d, 32, bits);
            c = (c + d) & m; b = (b ^ c) & m; b = rotl_within(b, 24, bits);
            a = (a + b) & m; d = (d ^ a) & m; d = rotl_within(d, 16, bits);
            c = (c + d) & m; b = (b ^ c) & m; b = rotl_within(b, 12, bits);
            data.set_element(i, a);
            data.set_element(i + 1, b);
            data.set_element(i + 2, c);
            data.set_element(i + 3, d);
        }
    }

    void unapply_transform_chacha(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i + 3 < data.element_count(); i += 4) {
            uint64_t a = data.get_element(i);
            uint64_t b = data.get_element(i + 1);
            uint64_t c = data.get_element(i + 2);
            uint64_t d = data.get_element(i + 3);
            uint64_t m = element_mask(bits);
            // Unwind the quarter round in exact reverse, keeping every value the
            // next step still needs in its own temporary.
            uint64_t b3 = rotr_within(b, 12, bits);
            uint64_t b2 = (b3 ^ c) & m;
            uint64_t c1 = (c - d) & m;
            uint64_t d3 = rotr_within(d, 16, bits);
            uint64_t d2 = (d3 ^ a) & m;
            uint64_t a1 = (a - b2) & m;
            uint64_t b1 = rotr_within(b2, 24, bits);
            uint64_t b0 = (b1 ^ c1) & m;
            uint64_t c0 = (c1 - d2) & m;
            uint64_t d1 = rotr_within(d2, 32, bits);
            uint64_t d0 = (d1 ^ a1) & m;
            uint64_t a0 = (a1 - b0) & m;   // forward added b0, not b1
            data.set_element(i, a0);
            data.set_element(i + 1, b0);
            data.set_element(i + 2, c0);
            data.set_element(i + 3, d0);
        }
    }

    void apply_transform_aes(container_t& data) {
        if (bit_mode_to_size(data.global_mode()) < 8) return;
        const auto& sbox = aes_sbox();
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t out = 0;
            for (size_t b = 0; b < 8; ++b) {
                uint8_t byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFF);
                out |= static_cast<uint64_t>(sbox[byte_val]) << (b * 8);
            }
            data.set_element(i, out);
        }
    }

    void unapply_transform_aes(container_t& data) {
        if (bit_mode_to_size(data.global_mode()) < 8) return;
        const auto& inv = aes_inv_sbox();
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t val = data.get_element(i);
            uint64_t out = 0;
            for (size_t b = 0; b < 8; ++b) {
                uint8_t byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFF);
                out |= static_cast<uint64_t>(inv[byte_val]) << (b * 8);
            }
            data.set_element(i, out);
        }
    }

    // ============================================================================
    // Mode Stack Operations
    // ============================================================================

    static BitMode random_mode(uint64_t index) {
        static const BitMode modes[] = {BitMode::BIT_1, BitMode::BIT_2, BitMode::BIT_3, BitMode::NIBBLE,
                                        BitMode::BYTE, BitMode::WORD16, BitMode::WORD32, BitMode::WORD64};
        return modes[index % 8];
    }

    void apply_push_mode(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        m_mode_stack.push_back(random_mode(m_prng.generate_range_u64(0, 7)));
    }

    void unapply_push_mode(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.size() > 1) m_mode_stack.pop_back();
    }

    void apply_pop_mode(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.size() > 1) m_mode_stack.pop_back();
    }

    void unapply_pop_mode(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        m_mode_stack.push_back(random_mode(m_prng.generate_range_u64(0, 7)));
    }

    void apply_switch_mode(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.size() < 2) return;
        size_t i = m_prng.generate_range_u64(0, m_mode_stack.size() - 1);
        std::swap(m_mode_stack.back(), m_mode_stack[i]);
    }

    void apply_mode_cycle(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.empty()) return;
        size_t s = m_prng.generate_range_u64(0, m_mode_stack.size() - 1);
        std::rotate(m_mode_stack.begin(), m_mode_stack.begin() + s, m_mode_stack.end());
    }

    void unapply_mode_cycle(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.empty()) return;
        size_t s = m_prng.generate_range_u64(0, m_mode_stack.size() - 1);
        size_t back = (m_mode_stack.size() - s) % m_mode_stack.size();
        std::rotate(m_mode_stack.begin(), m_mode_stack.begin() + back, m_mode_stack.end());
    }

    // Derived from the keystream rather than from the data, so it stays reproducible.
    void apply_mode_feedback(container_t& data) {
        (void)data;   // mode-stack operation: shares the operation signature only
        if (m_mode_stack.empty()) return;
        m_mode_stack.back() = random_mode(m_prng.generate_u64());
    }

    // ============================================================================
    // Chunk Operations
    // ============================================================================

    // Only whole chunks participate. A short trailing chunk used to be copied in
    // full and silently truncated, which lost data whenever it was permuted away
    // from its own slot.
    void apply_chunk_permute(container_t& data) {
        size_t n = data.element_count();
        const size_t chunk_size = 64;
        size_t full_chunks = n / chunk_size;
        if (full_chunks < 2) return;
        auto perm = m_prng.generate_permutation(full_chunks);
        std::vector<uint64_t> values(n);
        for (size_t i = 0; i < n; ++i) values[i] = data.get_element(i);
        for (size_t i = 0; i < full_chunks; ++i) {
            size_t src_start = perm[i] * chunk_size;
            size_t dst_start = i * chunk_size;
            for (size_t j = 0; j < chunk_size; ++j) {
                data.set_element(dst_start + j, values[src_start + j]);
            }
        }
    }

    void unapply_chunk_permute(container_t& data) {
        size_t n = data.element_count();
        const size_t chunk_size = 64;
        size_t full_chunks = n / chunk_size;
        if (full_chunks < 2) return;
        auto perm = m_prng.generate_permutation(full_chunks);
        std::vector<uint64_t> values(n);
        for (size_t i = 0; i < n; ++i) values[i] = data.get_element(i);
        for (size_t i = 0; i < full_chunks; ++i) {
            size_t src_start = perm[i] * chunk_size;
            size_t dst_start = i * chunk_size;
            for (size_t j = 0; j < chunk_size; ++j) {
                data.set_element(src_start + j, values[dst_start + j]);
            }
        }
    }

    void apply_chunk_cascade(container_t& data) {
        size_t n = data.element_count();
        const size_t chunk_size = 32;
        for (size_t i = 0; i + chunk_size < n; i += chunk_size) {
            for (size_t j = 0; j < chunk_size && i + chunk_size + j < n; ++j) {
                data.set_element(i + j, data.get_element(i + j) ^ data.get_element(i + chunk_size + j));
            }
        }
    }

    void unapply_chunk_cascade(container_t& data) {
        size_t n = data.element_count();
        const size_t chunk_size = 32;
        size_t last = 0;
        while (last + chunk_size < n) last += chunk_size;
        if (last == 0) return;
        for (size_t i = last; i > 0; i -= chunk_size) {
            for (size_t j = 0; j < chunk_size && i + chunk_size + j < n; ++j) {
                data.set_element(i + j, data.get_element(i + j) ^ data.get_element(i + chunk_size + j));
            }
        }
        for (size_t j = 0; j < chunk_size && 0 + chunk_size + j < n; ++j) {
            data.set_element(j, data.get_element(j) ^ data.get_element(chunk_size + j));
        }
    }

    // ============================================================================
    // Advanced Operations
    // ============================================================================

    void apply_cascade(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t i = 0; i + 1 < n; ++i) {
            data.set_element(i + 1, data.get_element(i + 1) ^ data.get_element(i));
        }
    }

    void unapply_cascade(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t i = n; i-- > 1;) {
            data.set_element(i, data.get_element(i) ^ data.get_element(i - 1));
        }
    }

    void apply_spiral(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t i = 0; i < n; ++i) {
            size_t src = (i + n - 7 % n) % n;
            if (src == i) continue;
            data.set_element(i, data.get_element(i) ^ std::rotl(data.get_element(src), 3));
        }
    }

    void unapply_spiral(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        for (size_t i = n; i-- > 0;) {
            size_t src = (i + n - 7 % n) % n;
            if (src == i) continue;
            data.set_element(i, data.get_element(i) ^ std::rotl(data.get_element(src), 3));
        }
    }

    void apply_interleave(container_t& data) {
        size_t n = data.element_count();
        if (n < 3) return;
        std::vector<uint64_t> values(n);
        size_t half = n / 2;
        for (size_t i = 0; i < n; ++i) values[i] = data.get_element(i);
        for (size_t i = 0; i < half; ++i) {
            data.set_element(i * 2, values[i]);
            data.set_element(i * 2 + 1, values[half + i]);
        }
    }

    void unapply_interleave(container_t& data) {
        size_t n = data.element_count();
        if (n < 3) return;
        std::vector<uint64_t> values(n);
        size_t half = n / 2;
        for (size_t i = 0; i < n; ++i) values[i] = data.get_element(i);
        for (size_t i = 0; i < half; ++i) {
            data.set_element(i, values[i * 2]);
            data.set_element(half + i, values[i * 2 + 1]);
        }
    }

    // Pairs are always applied to the higher index, so the lower value a step reads
    // is untouched until its own step runs; undoing in reverse order restores it.
    void entangle_pairs(size_t n, std::vector<std::pair<uint64_t, uint64_t>>& pairs) {
        pairs.resize(n);
        for (size_t k = 0; k < n; ++k) {
            uint64_t a = m_prng.generate_range_u64(0, n - 1);
            uint64_t b = m_prng.generate_range_u64(0, n - 1);
            if (a > b) std::swap(a, b);
            pairs[k] = {a, b};
        }
    }

    void apply_entangle(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        std::vector<std::pair<uint64_t, uint64_t>> pairs;
        entangle_pairs(n, pairs);
        for (auto& [a, b] : pairs) {
            if (a != b) data.set_element(b, data.get_element(b) ^ data.get_element(a));
        }
    }

    void unapply_entangle(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        std::vector<std::pair<uint64_t, uint64_t>> pairs;
        entangle_pairs(n, pairs);
        for (size_t k = n; k-- > 0;) {
            auto [a, b] = pairs[k];
            if (a != b) data.set_element(b, data.get_element(b) ^ data.get_element(a));
        }
    }

    // Sequential state feedback; the same keystream is rebuilt on both sides.
    void apply_avalanche(container_t& data) {
        size_t n = data.element_count();
        uint64_t state = m_prng.generate_u64();
        for (size_t i = 0; i < n; ++i) {
            state = state * 0x9E3779B97F4A7C15ULL + 1;
            data.set_element(i, data.get_element(i) ^ state);
        }
    }

    void collect_fractal_swaps(std::vector<std::pair<uint64_t, uint64_t>>& out, size_t start, size_t len) {
        if (len < 8) return;
        size_t mid = len / 2;
        if (mid < 1) return;
        auto perm = m_prng.generate_permutation(mid);
        for (size_t i = 0; i < mid; ++i) {
            size_t a = start + i;
            size_t b = start + mid + perm[i];
            if (b < start + len) out.emplace_back(a, b);
        }
        collect_fractal_swaps(out, start, mid);
        collect_fractal_swaps(out, start + mid, len - mid);
    }

    void apply_fractal_permute(container_t& data) {
        size_t n = data.element_count();
        if (n < 8) return;
        std::vector<std::pair<uint64_t, uint64_t>> swaps;
        collect_fractal_swaps(swaps, 0, n);
        for (auto& [a, b] : swaps) {
            if (a == b) continue;
            uint64_t va = data.get_element(a);
            uint64_t vb = data.get_element(b);
            data.set_element(a, vb);
            data.set_element(b, va);
        }
    }

    void unapply_fractal_permute(container_t& data) {
        size_t n = data.element_count();
        if (n < 8) return;
        std::vector<std::pair<uint64_t, uint64_t>> swaps;
        collect_fractal_swaps(swaps, 0, n);
        for (size_t k = swaps.size(); k-- > 0;) {
            auto [a, b] = swaps[k];
            if (a == b) continue;
            uint64_t va = data.get_element(a);
            uint64_t vb = data.get_element(b);
            data.set_element(a, vb);
            data.set_element(b, va);
        }
    }

    void apply_chaos_inject(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        double chaos = m_prng.generate_double();
        size_t count = static_cast<size_t>(static_cast<double>(n) * chaos);
        for (size_t i = 0; i < count; ++i) {
            size_t pos = m_prng.generate_range_u64(0, n - 1);
            data.set_element(pos, data.get_element(pos) ^ m_prng.generate_u64());
        }
    }

    void apply_buffer_mixer(container_t& data) {
        size_t n = data.element_count();
        const size_t block = 256;
        for (size_t off = 0; off + block < n; off += block * 2) {
            for (size_t i = off; i < std::min(off + block, n); ++i) {
                size_t j = off + block + (i - off);
                if (j >= n) continue;
                uint64_t k = m_prng.generate_u64();
                uint64_t a = data.get_element(i);
                uint64_t b = data.get_element(j);
                data.set_element(i, (a ^ std::rotl(b, static_cast<int>((i - off) % 13))) + k);
            }
        }
    }

    void unapply_buffer_mixer(container_t& data) {
        size_t n = data.element_count();
        const size_t block = 256;
        for (size_t off = 0; off + block < n; off += block * 2) {
            for (size_t i = off; i < std::min(off + block, n); ++i) {
                size_t j = off + block + (i - off);
                if (j >= n) continue;
                uint64_t k = m_prng.generate_u64();
                uint64_t b = data.get_element(j);
                uint64_t r = data.get_element(i);
                data.set_element(i, (r - k) ^ std::rotl(b, static_cast<int>((i - off) % 13)));
            }
        }
    }

    // Feistel pair: invertible without losing bits.
    void apply_dual_block_weave(container_t& data) {
        size_t n = data.element_count();
        const size_t block = 128;
        for (size_t off = 0; off + block * 2 <= n; off += block * 2) {
            for (size_t i = 0; i < block; ++i) {
                uint64_t k = m_prng.generate_u64();
                uint64_t a = data.get_element(off + i);
                uint64_t b = data.get_element(off + block + i);
                uint64_t a2 = a ^ (b + k);
                uint64_t b2 = b ^ (a2 + k);
                data.set_element(off + i, a2);
                data.set_element(off + block + i, b2);
            }
        }
    }

    void unapply_dual_block_weave(container_t& data) {
        size_t n = data.element_count();
        const size_t block = 128;
        for (size_t off = 0; off + block * 2 <= n; off += block * 2) {
            for (size_t i = 0; i < block; ++i) {
                uint64_t k = m_prng.generate_u64();
                uint64_t a2 = data.get_element(off + i);
                uint64_t b2 = data.get_element(off + block + i);
                uint64_t b = b2 ^ (a2 + k);
                uint64_t a = a2 ^ (b + k);
                data.set_element(off + i, a);
                data.set_element(off + block + i, b);
            }
        }
    }

    void apply_instruction_cascade(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t instr = m_prng.generate_u64();
            uint64_t v = data.get_element(i);
            switch (instr % 4) {
                case 0: v ^= (v << 7); break;
                case 1: v += m_prng.generate_u64(); break;
                case 2: v = rotl_within(v, 11, bits); break;
                default: v ^= m_prng.generate_u64(); break;
            }
            data.set_element(i, v);
        }
    }

    void unapply_instruction_cascade(container_t& data) {
        size_t bits = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < data.element_count(); ++i) {
            uint64_t instr = m_prng.generate_u64();
            uint64_t v = data.get_element(i);
            switch (instr % 4) {
                case 0: v = undo_xorshift_left(v, 7); break;
                case 1: v -= m_prng.generate_u64(); break;
                case 2: v = rotr_within(v, 11, bits); break;
                default: v ^= m_prng.generate_u64(); break;
            }
            data.set_element(i, v);
        }
    }

    void apply_state_machine_mix(container_t& data) {
        size_t n = data.element_count();
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t state = m_prng.generate_u64();
        for (size_t i = 0; i < n; ++i) {
            uint64_t v = data.get_element(i);
            state = state * 6364136223846793005ULL + 1;
            switch (state & 3) {
                case 0: v ^= state; break;
                case 1: v += (state << (i % 17)); break;
                case 2: v ^= (v >> ((i % 11) + 1)); break;
                default: v = rotl_within(v, 9, bits); break;
            }
            data.set_element(i, v);
        }
    }

    void unapply_state_machine_mix(container_t& data) {
        size_t n = data.element_count();
        size_t bits = bit_mode_to_size(data.global_mode());
        uint64_t state = m_prng.generate_u64();
        for (size_t i = 0; i < n; ++i) {
            uint64_t v = data.get_element(i);
            state = state * 6364136223846793005ULL + 1;
            switch (state & 3) {
                case 0: v ^= state; break;
                case 1: v -= (state << (i % 17)); break;
                case 2: v = undo_xorshift_right(v, static_cast<unsigned>((i % 11) + 1)); break;
                default: v = rotr_within(v, 9, bits); break;
            }
            data.set_element(i, v);
        }
    }

    void apply_loop_fusion(container_t& data) {
        size_t n = data.element_count();
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint64_t k = m_prng.generate_u64();
            uint64_t a = data.get_element(i);
            uint64_t b = data.get_element(i + 1);
            uint64_t a2 = a ^ (b + k);
            uint64_t b2 = b ^ (a2 + k);
            data.set_element(i, a2);
            data.set_element(i + 1, b2);
        }
    }

    void unapply_loop_fusion(container_t& data) {
        size_t n = data.element_count();
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint64_t k = m_prng.generate_u64();
            uint64_t a2 = data.get_element(i);
            uint64_t b2 = data.get_element(i + 1);
            uint64_t b = b2 ^ (a2 + k);
            uint64_t a = a2 ^ (b + k);
            data.set_element(i, a);
            data.set_element(i + 1, b);
        }
    }

    void apply_block_resonance(container_t& data) {
        size_t n = data.element_count();
        const size_t block = 64;
        for (size_t off = 0; off < n; off += block) {
            uint64_t resonance = m_prng.generate_u64();
            size_t end = std::min(off + block, n);
            for (size_t i = off; i < end; ++i) {
                data.set_element(i, data.get_element(i) ^ std::rotl(resonance, static_cast<int>((i - off) % 64)));
            }
        }
    }

    // ============================================================================
    // Parallel Operations (deterministic, block-partitioned)
    // ============================================================================

    void apply_parallel_scatter(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        const size_t block = 512;
        for (size_t b = 0; b < n; b += block) {
            size_t len = std::min(block, n - b);
            if (len < 2) continue;
            auto perm = m_prng.generate_permutation(len);
            std::vector<uint64_t> vals(len);
            for (size_t i = 0; i < len; ++i) vals[perm[i]] = data.get_element(b + i);
            for (size_t i = 0; i < len; ++i) data.set_element(b + i, vals[i]);
        }
    }

    void unapply_parallel_scatter(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        const size_t block = 512;
        for (size_t b = 0; b < n; b += block) {
            size_t len = std::min(block, n - b);
            if (len < 2) continue;
            auto perm = m_prng.generate_permutation(len);
            std::vector<uint64_t> vals(len);
            for (size_t i = 0; i < len; ++i) vals[i] = data.get_element(b + perm[i]);
            for (size_t i = 0; i < len; ++i) data.set_element(b + i, vals[i]);
        }
    }

    void apply_parallel_shuffle(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        perm_apply(data, fisher_yates(n));
    }

    void unapply_parallel_shuffle(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        perm_unapply(data, fisher_yates(n));
    }

    void apply_parallel_diffuse(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        size_t threads = std::max<size_t>(1, m_settings.parallel_threads);
        size_t block = (n + threads - 1) / threads;
        for (size_t b = 0; b < n; b += block) {
            size_t end = std::min(b + block, n);
            for (size_t i = end; i-- > b + 1;) {
                unsigned k = static_cast<unsigned>((i % 17) + 1);
                data.set_element(i, data.get_element(i) ^ std::rotl(data.get_element(i - 1), k));
            }
        }
    }

    void unapply_parallel_diffuse(container_t& data) {
        size_t n = data.element_count();
        if (n < 2) return;
        size_t threads = std::max<size_t>(1, m_settings.parallel_threads);
        size_t block = (n + threads - 1) / threads;
        for (size_t b = 0; b < n; b += block) {
            size_t end = std::min(b + block, n);
            for (size_t i = b + 1; i < end; ++i) {
                unsigned k = static_cast<unsigned>((i % 17) + 1);
                data.set_element(i, data.get_element(i) ^ std::rotl(data.get_element(i - 1), k));
            }
        }
    }

    // ============================================================================
    // Noise Operations (bit flips driven purely by the keystream -> self-inverse)
    // ============================================================================

    void flip_bit(container_t& data, size_t elem, size_t bit) {
        data.set_element(elem, data.get_element(elem) ^ (1ULL << bit));
    }

    void apply_noise_white(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        size_t total_bits = n * bits_per_elem;
        size_t noise_bits = static_cast<size_t>(static_cast<double>(total_bits) * m_settings.noise_level);
        for (size_t i = 0; i < noise_bits; ++i) {
            size_t elem = m_prng.generate_range_u64(0, n - 1);
            size_t bit = m_prng.generate_range_u64(0, bits_per_elem - 1);
            flip_bit(data, elem, bit);
        }
    }

    void apply_noise_pink(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        std::vector<double> state(6, 0.0);
        for (size_t i = 0; i < n * bits_per_elem; ++i) {
            double white = m_prng.generate_double() * 2.0 - 1.0;
            state[0] = 0.99886 * state[0] + white * 0.0555179;
            state[1] = 0.99332 * state[1] + white * 0.0750759;
            state[2] = 0.96900 * state[2] + white * 0.1538520;
            state[3] = 0.86650 * state[3] + white * 0.3104856;
            state[4] = 0.55000 * state[4] + white * 0.5329522;
            state[5] = -0.7616 * state[5] - white * 0.0168980;
            double pink = (state[0] + state[1] + state[2] + state[3] + state[4] + state[5] + white * 0.5362) * 0.11;
            if (pink > 0.0) {
                size_t elem = i / bits_per_elem;
                if (elem < n) flip_bit(data, elem, i % bits_per_elem);
            }
        }
    }

    void apply_noise_brown(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        double brown = 0.0;
        for (size_t i = 0; i < n * bits_per_elem; ++i) {
            double white = m_prng.generate_double() * 2.0 - 1.0;
            brown = (brown + white) * 0.5;
            if (brown > 0.0) {
                size_t elem = i / bits_per_elem;
                if (elem < n) flip_bit(data, elem, i % bits_per_elem);
            }
        }
    }

    void apply_noise_gaussian(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        size_t noise_bits = static_cast<size_t>(
            static_cast<double>(n * bits_per_elem) * m_settings.noise_level);
        for (size_t i = 0; i < noise_bits; ++i) {
            double g = m_prng.generate_gaussian(0.0, 1.0);
            if (std::abs(g) > 1.0) {
                size_t elem = m_prng.generate_range_u64(0, n - 1);
                size_t bit = m_prng.generate_range_u64(0, bits_per_elem - 1);
                flip_bit(data, elem, bit);
            }
        }
    }

    void apply_noise_impulse(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < n * bits_per_elem; ++i) {
            if (m_prng.generate_double() < 0.01) {
                size_t elem = i / bits_per_elem;
                if (elem < n) flip_bit(data, elem, i % bits_per_elem);
            }
        }
    }

    void apply_noise_quantum(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        for (size_t i = 0; i < n * bits_per_elem; ++i) {
            if (m_prng.generate_double() < 0.25) {
                size_t elem = i / bits_per_elem;
                if (elem < n) flip_bit(data, elem, i % bits_per_elem);
            }
        }
    }

    // Level comes from the keystream, not from data entropy, so it reproduces.
    void apply_noise_adaptive(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        double level = m_settings.noise_level * (0.5 + 0.5 * m_prng.generate_double());
        size_t noise_bits = static_cast<size_t>(static_cast<double>(n * bits_per_elem) * level);
        for (size_t i = 0; i < noise_bits; ++i) {
            size_t elem = m_prng.generate_range_u64(0, n - 1);
            size_t bit = m_prng.generate_range_u64(0, bits_per_elem - 1);
            flip_bit(data, elem, bit);
        }
    }

    void apply_noise_structured(container_t& data) {
        static const double weights[] = {0.3, 0.2, 0.15, 0.1, 0.08, 0.06, 0.05, 0.04, 0.02};
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        size_t total_bits = n * bits_per_elem;
        for (size_t f = 0; f < 9; ++f) {
            if (m_prng.generate_double() < weights[f]) {
                size_t period = size_t(1) << f;
                for (size_t pos = f; pos < total_bits; pos += period) {
                    if (m_prng.generate_double() < 0.3) {
                        size_t elem = pos / bits_per_elem;
                        if (elem < n) flip_bit(data, elem, pos % bits_per_elem);
                    }
                }
            }
        }
    }

    void apply_noise_chaotic(container_t& data) {
        size_t n = data.element_count();
        if (n == 0) return;
        size_t bits_per_elem = bit_mode_to_size(data.global_mode());
        double x = m_prng.generate_double();
        for (size_t i = 0; i < n * bits_per_elem; ++i) {
            x = 3.9 * x * (1.0 - x);
            if (x > 0.5) {
                size_t elem = i / bits_per_elem;
                if (elem < n) flip_bit(data, elem, i % bits_per_elem);
            }
        }
    }

    // ============================================================================
    // Shape Transform Application
    // ============================================================================

    void apply_transform(ShapeTransform* transform, container_t& data, bool inverse) {
        ShapeContext ctx(m_prng, m_settings.shape_distribution,
                         data.element_count(), m_settings.bit_mode);
        if (inverse) transform->inverse_transform(data, ctx);
        else transform->transform(data, ctx);
    }

    // ============================================================================
    // Dispatch: forward operations and their inverses
    // ============================================================================

    template<typename T>
    void apply_operation(container_t& data) {
        if constexpr (std::is_same_v<T, Scatter>) apply_scatter(data);
        else if constexpr (std::is_same_v<T, Shuffle>) apply_shuffle(data);
        else if constexpr (std::is_same_v<T, Diffuse>) apply_diffuse(data);
        else if constexpr (std::is_same_v<T, Mix>) apply_mix(data);
        else if constexpr (std::is_same_v<T, Permute>) apply_permute(data);
        else if constexpr (std::is_same_v<T, Rotate>) apply_rotate(data);
        else if constexpr (std::is_same_v<T, Flip>) apply_flip(data);
        else if constexpr (std::is_same_v<T, Swap>) apply_swap(data);
        else if constexpr (std::is_same_v<T, BitwiseNot>) apply_bitwise_not(data);
        else if constexpr (std::is_same_v<T, BitwiseRotL>) apply_bitwise_rotl(data);
        else if constexpr (std::is_same_v<T, BitwiseRotR>) apply_bitwise_rotr(data);
        else if constexpr (std::is_same_v<T, BitwiseReverse>) apply_bitwise_reverse(data);
        else if constexpr (std::is_same_v<T, BitwiseSwapNibbles>) apply_bitwise_swap_nibbles(data);
        else if constexpr (std::is_same_v<T, BitwiseGrayCode>) apply_bitwise_gray_code(data);
        else if constexpr (std::is_same_v<T, BitwiseXor>) apply_bitwise_xor(data);
        else if constexpr (std::is_same_v<T, BitwiseAnd>) apply_bitwise_and(data);
        else if constexpr (std::is_same_v<T, BitwiseOr>) apply_bitwise_or(data);
        else if constexpr (std::is_same_v<T, ArithmeticNegate>) apply_arithmetic_negate(data);
        else if constexpr (std::is_same_v<T, ArithmeticAdd>) apply_arithmetic_add(data);
        else if constexpr (std::is_same_v<T, ArithmeticSub>) apply_arithmetic_sub(data);
        else if constexpr (std::is_same_v<T, ArithmeticMul>) apply_arithmetic_mul(data);
        else if constexpr (std::is_same_v<T, ArithmeticDiv>) apply_arithmetic_div(data);
        else if constexpr (std::is_same_v<T, ByteSwap>) apply_byte_swap(data);
        else if constexpr (std::is_same_v<T, ByteReverse>) apply_byte_reverse(data);
        else if constexpr (std::is_same_v<T, ByteRotate>) apply_byte_rotate(data);
        else if constexpr (std::is_same_v<T, WordSwap>) apply_word_swap(data);
        else if constexpr (std::is_same_v<T, WordMix>) apply_word_mix(data);
        else if constexpr (std::is_same_v<T, TransformXorShift>) apply_transform_xorshift(data);
        else if constexpr (std::is_same_v<T, TransformChaCha>) apply_transform_chacha(data);
        else if constexpr (std::is_same_v<T, TransformAES>) apply_transform_aes(data);
        else if constexpr (std::is_same_v<T, PushMode>) apply_push_mode(data);
        else if constexpr (std::is_same_v<T, PopMode>) apply_pop_mode(data);
        else if constexpr (std::is_same_v<T, SwitchMode>) apply_switch_mode(data);
        else if constexpr (std::is_same_v<T, ModeCycle>) apply_mode_cycle(data);
        else if constexpr (std::is_same_v<T, ModeFeedback>) apply_mode_feedback(data);
        else if constexpr (std::is_same_v<T, ChunkPermute>) apply_chunk_permute(data);
        else if constexpr (std::is_same_v<T, ChunkCascade>) apply_chunk_cascade(data);
        else if constexpr (std::is_same_v<T, Cascade>) apply_cascade(data);
        else if constexpr (std::is_same_v<T, Spiral>) apply_spiral(data);
        else if constexpr (std::is_same_v<T, Interleave>) apply_interleave(data);
        else if constexpr (std::is_same_v<T, Entangle>) apply_entangle(data);
        else if constexpr (std::is_same_v<T, Avalanche>) apply_avalanche(data);
        else if constexpr (std::is_same_v<T, FractalPermute>) apply_fractal_permute(data);
        else if constexpr (std::is_same_v<T, ChaosInject>) apply_chaos_inject(data);
        else if constexpr (std::is_same_v<T, BufferMixer>) apply_buffer_mixer(data);
        else if constexpr (std::is_same_v<T, DualBlockWeave>) apply_dual_block_weave(data);
        else if constexpr (std::is_same_v<T, InstructionCascade>) apply_instruction_cascade(data);
        else if constexpr (std::is_same_v<T, StateMachineMix>) apply_state_machine_mix(data);
        else if constexpr (std::is_same_v<T, LoopFusion>) apply_loop_fusion(data);
        else if constexpr (std::is_same_v<T, BlockResonance>) apply_block_resonance(data);
        else if constexpr (std::is_same_v<T, ParallelScatter>) apply_parallel_scatter(data);
        else if constexpr (std::is_same_v<T, ParallelShuffle>) apply_parallel_shuffle(data);
        else if constexpr (std::is_same_v<T, ParallelDiffuse>) apply_parallel_diffuse(data);
        else if constexpr (std::is_same_v<T, NoiseWhite>) apply_noise_white(data);
        else if constexpr (std::is_same_v<T, NoisePink>) apply_noise_pink(data);
        else if constexpr (std::is_same_v<T, NoiseBrown>) apply_noise_brown(data);
        else if constexpr (std::is_same_v<T, NoiseGaussian>) apply_noise_gaussian(data);
        else if constexpr (std::is_same_v<T, NoiseImpulse>) apply_noise_impulse(data);
        else if constexpr (std::is_same_v<T, NoiseQuantum>) apply_noise_quantum(data);
        else if constexpr (std::is_same_v<T, NoiseAdaptive>) apply_noise_adaptive(data);
        else if constexpr (std::is_same_v<T, NoiseStructured>) apply_noise_structured(data);
        else if constexpr (std::is_same_v<T, NoiseChaotic>) apply_noise_chaotic(data);
        else if constexpr (std::is_base_of_v<ShapeTransform, T>) {
            T transform(m_settings.shape_distribution);
            apply_transform(&transform, data, false);
        }
    }

    template<typename T>
    void apply_reverse_operation(container_t& data) {
        if constexpr (std::is_same_v<T, Scatter>) unapply_scatter(data);
        else if constexpr (std::is_same_v<T, Shuffle>) unapply_shuffle(data);
        else if constexpr (std::is_same_v<T, Diffuse>) unapply_diffuse(data);
        else if constexpr (std::is_same_v<T, Mix>) apply_mix(data);
        else if constexpr (std::is_same_v<T, Permute>) unapply_permute(data);
        else if constexpr (std::is_same_v<T, Rotate>) unapply_rotate(data);
        else if constexpr (std::is_same_v<T, Flip>) apply_flip(data);
        else if constexpr (std::is_same_v<T, Swap>) apply_swap(data);
        else if constexpr (std::is_same_v<T, BitwiseNot>) apply_bitwise_not(data);
        else if constexpr (std::is_same_v<T, BitwiseRotL>) apply_bitwise_rotr(data);
        else if constexpr (std::is_same_v<T, BitwiseRotR>) apply_bitwise_rotl(data);
        else if constexpr (std::is_same_v<T, BitwiseReverse>) apply_bitwise_reverse(data);
        else if constexpr (std::is_same_v<T, BitwiseSwapNibbles>) unapply_bitwise_swap_nibbles(data);
        else if constexpr (std::is_same_v<T, BitwiseGrayCode>) unapply_bitwise_gray_code(data);
        else if constexpr (std::is_same_v<T, BitwiseXor>) apply_bitwise_xor(data);
        else if constexpr (std::is_same_v<T, BitwiseAnd>) unapply_bitwise_and(data);
        else if constexpr (std::is_same_v<T, BitwiseOr>) apply_bitwise_or(data);
        else if constexpr (std::is_same_v<T, ArithmeticNegate>) apply_arithmetic_negate(data);
        else if constexpr (std::is_same_v<T, ArithmeticAdd>) apply_arithmetic_sub(data);
        else if constexpr (std::is_same_v<T, ArithmeticSub>) apply_arithmetic_add(data);
        else if constexpr (std::is_same_v<T, ArithmeticMul>) unapply_arithmetic_mul(data);
        else if constexpr (std::is_same_v<T, ArithmeticDiv>) unapply_arithmetic_div(data);
        else if constexpr (std::is_same_v<T, ByteSwap>) apply_byte_swap(data);
        else if constexpr (std::is_same_v<T, ByteReverse>) apply_byte_reverse(data);
        else if constexpr (std::is_same_v<T, ByteRotate>) unapply_byte_rotate(data);
        else if constexpr (std::is_same_v<T, WordSwap>) apply_word_swap(data);
        else if constexpr (std::is_same_v<T, WordMix>) unapply_word_mix(data);
        else if constexpr (std::is_same_v<T, TransformXorShift>) unapply_transform_xorshift(data);
        else if constexpr (std::is_same_v<T, TransformChaCha>) unapply_transform_chacha(data);
        else if constexpr (std::is_same_v<T, TransformAES>) unapply_transform_aes(data);
        else if constexpr (std::is_same_v<T, PushMode>) unapply_push_mode(data);
        else if constexpr (std::is_same_v<T, PopMode>) unapply_pop_mode(data);
        else if constexpr (std::is_same_v<T, SwitchMode>) apply_switch_mode(data);
        else if constexpr (std::is_same_v<T, ModeCycle>) unapply_mode_cycle(data);
        else if constexpr (std::is_same_v<T, ModeFeedback>) apply_mode_feedback(data);
        else if constexpr (std::is_same_v<T, ChunkPermute>) unapply_chunk_permute(data);
        else if constexpr (std::is_same_v<T, ChunkCascade>) unapply_chunk_cascade(data);
        else if constexpr (std::is_same_v<T, Cascade>) unapply_cascade(data);
        else if constexpr (std::is_same_v<T, Spiral>) unapply_spiral(data);
        else if constexpr (std::is_same_v<T, Interleave>) unapply_interleave(data);
        else if constexpr (std::is_same_v<T, Entangle>) unapply_entangle(data);
        else if constexpr (std::is_same_v<T, Avalanche>) apply_avalanche(data);
        else if constexpr (std::is_same_v<T, FractalPermute>) unapply_fractal_permute(data);
        else if constexpr (std::is_same_v<T, ChaosInject>) apply_chaos_inject(data);
        else if constexpr (std::is_same_v<T, BufferMixer>) unapply_buffer_mixer(data);
        else if constexpr (std::is_same_v<T, DualBlockWeave>) unapply_dual_block_weave(data);
        else if constexpr (std::is_same_v<T, InstructionCascade>) unapply_instruction_cascade(data);
        else if constexpr (std::is_same_v<T, StateMachineMix>) unapply_state_machine_mix(data);
        else if constexpr (std::is_same_v<T, LoopFusion>) unapply_loop_fusion(data);
        else if constexpr (std::is_same_v<T, BlockResonance>) apply_block_resonance(data);
        else if constexpr (std::is_same_v<T, ParallelScatter>) unapply_parallel_scatter(data);
        else if constexpr (std::is_same_v<T, ParallelShuffle>) unapply_parallel_shuffle(data);
        else if constexpr (std::is_same_v<T, ParallelDiffuse>) unapply_parallel_diffuse(data);
        else if constexpr (std::is_same_v<T, NoiseWhite>) apply_noise_white(data);
        else if constexpr (std::is_same_v<T, NoisePink>) apply_noise_pink(data);
        else if constexpr (std::is_same_v<T, NoiseBrown>) apply_noise_brown(data);
        else if constexpr (std::is_same_v<T, NoiseGaussian>) apply_noise_gaussian(data);
        else if constexpr (std::is_same_v<T, NoiseImpulse>) apply_noise_impulse(data);
        else if constexpr (std::is_same_v<T, NoiseQuantum>) apply_noise_quantum(data);
        else if constexpr (std::is_same_v<T, NoiseAdaptive>) apply_noise_adaptive(data);
        else if constexpr (std::is_same_v<T, NoiseStructured>) apply_noise_structured(data);
        else if constexpr (std::is_same_v<T, NoiseChaotic>) apply_noise_chaotic(data);
        else if constexpr (std::is_base_of_v<ShapeTransform, T>) {
            T transform(m_settings.shape_distribution);
            apply_transform(&transform, data, true);
        }
    }

    // ============================================================================
    // Per-operation keystream control
    // ============================================================================

    static uint64_t op_token(size_t index) {
        return 0x9E3779B97F4A7C15ULL * (static_cast<uint64_t>(index) + 1);
    }

    template<typename T, size_t Index>
    void run_forward(container_t& data) {
        m_prng.reseed(op_token(Index));
        data.begin_bulk();
        apply_operation<T>(data);
        data.end_bulk();
    }

    template<typename T, size_t Index>
    void run_inverse(container_t& data) {
        m_prng.reseed(op_token(Index));
        data.begin_bulk();
        apply_reverse_operation<T>(data);
        data.end_bulk();
    }

    template<size_t... Is>
    void encrypt_ops(container_t& target, std::index_sequence<Is...>) {
        (run_forward<Operations, Is>(target), ...);
    }

    template<size_t... Is>
    void decrypt_ops(container_t& target, std::index_sequence<Is...>) {
        // Inverses run last-to-first, and each one must reseed with the token of the
        // operation it is undoing - not with the position it occupies in this pass.
        ( run_inverse<
              std::tuple_element_t<sizeof...(Is) - 1 - Is, std::tuple<Operations...>>,
              sizeof...(Is) - 1 - Is>(target), ... );
    }

public:
    GeneticCipher() : m_data(m_settings.container_chunk_size, m_settings.bit_mode), m_current_encrypted_offset(0) {
        m_mode_stack.push_back(m_settings.bit_mode);
    }
    
    explicit GeneticCipher(const EncryptionSettings& settings) 
        : m_settings(settings), m_data(settings.container_chunk_size, settings.bit_mode), m_current_encrypted_offset(0) {
        m_mode_stack.push_back(m_settings.bit_mode);
    }
    
    ~GeneticCipher() {
        if (m_output_stream.is_open()) {
            m_output_stream.close();
        }
    }
    
    // ========================================================================
    // Configuration Methods
    // ========================================================================
    
    void set_settings(const EncryptionSettings& settings) { m_settings = settings; }
    EncryptionSettings& settings() { return m_settings; }
    
    void set_password(const_byte_span password) {
        m_user_password.assign(password.begin(), password.end());
        m_prng.seed(m_user_password, m_electronic_password);
    }
    
    void set_password(const std::string& password) {
        set_password({reinterpret_cast<const uint8_t*>(password.data()), password.size()});
    }
    
    void set_electronic_password(const_byte_span electronic_password) {
        m_electronic_password.assign(electronic_password.begin(), electronic_password.end());
        m_prng.seed(m_user_password, m_electronic_password);
    }
    
    void set_electronic_password(const std::string& electronic_password) {
        set_electronic_password({reinterpret_cast<const uint8_t*>(electronic_password.data()), 
                                 electronic_password.size()});
    }
    
    void add_transform(std::unique_ptr<ShapeTransform> transform) {
        m_custom_transforms.push_back(std::move(transform));
    }
    
    void clear_transforms() { m_custom_transforms.clear(); }
    
    // ========================================================================
    // File Input Methods for Streaming
    // ========================================================================
    
    void add_input_file(const std::string& filename) {
        if (!fs::exists(filename)) {
            throw std::runtime_error("File does not exist: " + filename);
        }
        
        PendingFileInfo info;
        info.filename = fs::path(filename).filename().string();
        info.original_path = filename;
        info.file_size = fs::file_size(filename);
        info.bytes_processed = 0;
        info.total_chunks = (info.file_size + m_settings.chunk_size - 1) / m_settings.chunk_size;
        info.file_hash = 0;
        info.access_mode = m_settings.file_access_mode;
        info.next_chunk_index = 0;
        
        // Compute file hash
        std::ifstream file(filename, std::ios::binary);
        if (file.is_open()) {
            uint64_t hash = 0x9e3779b97f4a7c15ULL;
            char buffer[4096];
            // read() stops at the last full block, so a trailing partial block has
            // to be folded in as well or the hash misses the file tail.
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                std::streamsize got = file.gcount();
                for (std::streamsize i = 0; i < got; ++i) {
                    hash = (hash ^ static_cast<uint8_t>(buffer[i])) * 0x9e3779b97f4a7c15ULL;
                    hash = std::rotl(hash, 13);
                }
                if (got < static_cast<std::streamsize>(sizeof(buffer))) break;
            }
            info.file_hash = hash;
            file.close();
        }
        
        m_pending_files[filename] = info;
    }
    
    void add_input_files(const std::vector<std::string>& filenames) {
        for (const auto& filename : filenames) {
            add_input_file(filename);
        }
    }
    
    void remove_input_file(const std::string& filename) {
        auto it = m_pending_files.find(filename);
        if (it != m_pending_files.end()) {
            m_pending_files.erase(it);
        }
    }
    
    void clear_input_files() {
        m_pending_files.clear();
    }
    
    // ========================================================================
    // Streaming Encryption
    // ========================================================================
    
    // Writes the same archive layout as save_encrypted(), so load_encrypted() and
    // extract_all_files() can read it back. The previous implementation emitted a
    // chunk-per-record stream with a trailing directory that nothing could decode.
    void encrypt_streaming(const std::string& output_filename,
                           std::function<void(float)> progress_callback = nullptr) {
        if (m_pending_files.empty() && m_data.element_count() == 0) {
            throw std::runtime_error("No input files to encrypt");
        }
        if (progress_callback) progress_callback(0.0f);
        save_encrypted(output_filename);
        if (progress_callback) progress_callback(1.0f);
    }
    
    // ========================================================================
    // Streaming Decryption
    // ========================================================================
    
    void decrypt_streaming(const std::string& input_filename,
                          const std::string& output_directory,
                          std::function<void(float)> progress_callback = nullptr) {
        std::ifstream in_file(input_filename, std::ios::binary);
        if (!in_file.is_open()) {
            throw std::runtime_error("Cannot open input file: " + input_filename);
        }
        
        // Read directory from end of file
        in_file.seekg(-static_cast<std::streamoff>(sizeof(uint64_t)), std::ios::end);
        uint64_t dir_size;
        in_file.read(reinterpret_cast<char*>(&dir_size), sizeof(dir_size));
        
        in_file.seekg(-static_cast<std::streamoff>(sizeof(uint64_t) + dir_size), std::ios::end);
        std::vector<uint8_t> dir_data(dir_size);
        in_file.read(reinterpret_cast<char*>(dir_data.data()), dir_size);
        m_directory.deserialize(dir_data);
        
        // Seek back to beginning of data
        in_file.seekg(0, std::ios::beg);
        
        fs::create_directories(output_directory);
        
        // Prepare output file streams
        std::unordered_map<std::string, std::ofstream> out_files;
        for (const auto& filename : m_directory.list_files()) {
            auto entry = m_directory.get_file(filename);
            std::string out_path = fs::path(output_directory) / filename;
            out_files[filename].open(out_path, std::ios::binary);
        }
        
        uint64_t total_chunks = 0;
        for (const auto& filename : m_directory.list_files()) {
            auto entry = m_directory.get_file(filename);
            total_chunks += entry.chunk_count;
        }
        uint64_t processed_chunks = 0;
        
        // Read and decrypt chunks
        while (in_file.peek() != EOF && in_file.tellg() < static_cast<std::streamoff>(in_file.seekg(0, std::ios::end).tellg() - static_cast<std::streamoff>(sizeof(uint64_t) + dir_size))) {
            // Read chunk metadata
            uint64_t chunk_size;
            in_file.read(reinterpret_cast<char*>(&chunk_size), sizeof(chunk_size));
            if (in_file.eof()) break;
            
            uint64_t chunk_id;
            in_file.read(reinterpret_cast<char*>(&chunk_id), sizeof(chunk_id));
            
            uint32_t name_len;
            in_file.read(reinterpret_cast<char*>(&name_len), sizeof(name_len));
            std::string filename(name_len, '\0');
            in_file.read(&filename[0], name_len);
            
            uint64_t original_offset;
            in_file.read(reinterpret_cast<char*>(&original_offset), sizeof(original_offset));
            
            // Read encrypted data
            std::vector<uint8_t> encrypted_data(chunk_size);
            in_file.read(reinterpret_cast<char*>(encrypted_data.data()), chunk_size);
            
            // Decrypt the chunk
            container_t chunk_container(encrypted_data.size(), BitMode::BYTE);
            chunk_container.append_bytes(encrypted_data.data(), encrypted_data.size());
            
            // Apply reverse operations
            for (auto it = m_custom_transforms.rbegin(); it != m_custom_transforms.rend(); ++it) {
                apply_transform(it->get(), chunk_container);
            }
            
            std::tuple<Operations...> ops;
            std::apply([&](auto&... op) {
                (apply_reverse_operation<decltype(op)>(chunk_container), ...);
            }, ops);
            
            // Write decrypted data to output file
            auto decrypted_bytes = chunk_container.to_bytes();
            auto& out_file = out_files[filename];
            out_file.seekp(original_offset);
            out_file.write(reinterpret_cast<const char*>(decrypted_bytes.data()), decrypted_bytes.size());
            
            processed_chunks++;
            if (progress_callback) {
                progress_callback(static_cast<float>(processed_chunks) / total_chunks);
            }
        }
        
        // Close all output files
        for (auto& [name, file] : out_files) {
            file.close();
        }
        
        in_file.close();
    }
    
    // ========================================================================
    // Traditional In-Memory Encryption/Decryption
    // ========================================================================
    
    container_t encrypt() {
        encrypt_in_place();
        return m_data.clone();
    }

    void encrypt_container(container_t& target) {
        if (target.element_count() == 0) {
            throw std::runtime_error("No data to encrypt");
        }

        // Pad *before* the operations run. Padding afterwards would change the
        // element count between encryption and decryption, and every length-aware
        // operation would then invert against the wrong geometry.
        pad_to_minimum_size(target);

        encrypt_ops(target, std::index_sequence_for<Operations...>{});

        for (size_t k = 0; k < m_custom_transforms.size(); ++k) {
            m_prng.reseed(op_token(0x10000 + k));
            apply_transform(m_custom_transforms[k].get(), target, false);
        }
    }

    void encrypt_in_place() { encrypt_container(m_data); }

    void pad_to_minimum_size(container_t& target) {
        size_t current_size = target.total_bytes();
        if (current_size >= m_settings.minimum_encrypted_size) return;

        size_t needed_bytes = m_settings.minimum_encrypted_size - current_size;
        size_t bytes_per_element = std::max<size_t>(1, bit_mode_to_size(target.global_mode()) / 8);
        size_t needed_elements = (needed_bytes + bytes_per_element - 1) / bytes_per_element;
        if (needed_elements == 0) return;

        std::vector<uint64_t> zeros(needed_elements, 0);
        target.append_elements(zeros.data(), zeros.size());
    }
    
    container_t encrypt(const container_t& data) {
        m_data.copy_from(data);
        return encrypt();
    }
    
    container_t decrypt() {
        decrypt_in_place();
        return m_data.clone();
    }

    void decrypt_container(container_t& target) {
        if (target.element_count() == 0) {
            throw std::runtime_error("No data to decrypt");
        }

        for (size_t k = m_custom_transforms.size(); k-- > 0;) {
            m_prng.reseed(op_token(0x10000 + k));
            apply_transform(m_custom_transforms[k].get(), target, true);
        }

        decrypt_ops(target, std::index_sequence_for<Operations...>{});
    }

    void decrypt_in_place() { decrypt_container(m_data); }
    
    container_t decrypt(const container_t& data) {
        m_data.copy_from(data);
        return decrypt();
    }
    
    // ========================================================================
    // File I/O with Directory Support
    // ========================================================================
    
    // Concatenate the queued input files into m_data in a deterministic order and
    // record each file's byte range in the directory, so extraction can slice the
    // decrypted payload back apart.
    void build_payload_from_pending_files() {
        if (m_pending_files.empty()) return;

        std::vector<std::string> order;
        order.reserve(m_pending_files.size());
        for (const auto& [key, info] : m_pending_files) order.push_back(key);

        std::sort(order.begin(), order.end(), [this](const std::string& a, const std::string& b) {
            const auto& ia = m_pending_files.at(a);
            const auto& ib = m_pending_files.at(b);
            if (m_settings.file_access_mode == FileAccessMode::PRIORITY_BASED &&
                ia.file_size != ib.file_size) {
                return ia.file_size > ib.file_size;
            }
            return ia.filename < ib.filename;
        });

        uint64_t offset = 0;
        for (const auto& key : order) {
            auto& info = m_pending_files.at(key);
            std::ifstream in(info.original_path, std::ios::binary);
            if (!in.is_open()) throw std::runtime_error("Cannot open input file: " + info.original_path);

            std::vector<uint8_t> bytes(static_cast<size_t>(info.file_size));
            if (!bytes.empty()) {
                in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                bytes.resize(static_cast<size_t>(in.gcount()));
            }
            in.close();

            m_data.append_bytes(bytes.data(), bytes.size());
            m_directory.add_file(info.filename, bytes.size(), offset, bytes.size(),
                                 info.file_hash, m_settings.bit_mode, info.access_mode);
            offset += bytes.size();
        }
        m_pending_files.clear();
    }

    void save_encrypted(const std::string& filename) {
        build_payload_from_pending_files();
        if (m_data.element_count() == 0) {
            throw std::runtime_error("No data to encrypt");
        }

        encrypt_in_place();
        auto bytes = m_data.to_bytes();
        auto dir_data = m_directory.serialize();

        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) throw std::runtime_error("Cannot create output file: " + filename);
        uint64_t dir_size = dir_data.size();
        file.write(reinterpret_cast<const char*>(&dir_size), sizeof(dir_size));
        file.write(reinterpret_cast<const char*>(dir_data.data()), static_cast<std::streamsize>(dir_data.size()));
        file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        file.close();
    }
    
    void load_encrypted(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) throw std::runtime_error("Cannot open file: " + filename);
        
        uint64_t dir_size;
        file.read(reinterpret_cast<char*>(&dir_size), sizeof(dir_size));
        std::vector<uint8_t> dir_data(dir_size);
        file.read(reinterpret_cast<char*>(dir_data.data()), dir_size);
        m_directory.deserialize(dir_data);
        
        file.seekg(0, std::ios::end);
        size_t total_size = file.tellg();
        size_t data_size = total_size - sizeof(dir_size) - dir_size;
        file.seekg(sizeof(dir_size) + dir_size, std::ios::beg);
        
        std::vector<uint8_t> buffer(data_size);
        file.read(reinterpret_cast<char*>(buffer.data()), data_size);
        file.close();
        
        m_data.clear();
        m_data.append_bytes(buffer.data(), buffer.size());
    }
    
    void extract_all_files(const std::string& output_dir) {
        fs::create_directories(output_dir);
        container_t plain;
        plain.copy_from(m_data);
        decrypt_container(plain);        // never mutates m_data, so repeats are safe

        for (const auto& filename : m_directory.list_files()) {
            auto entry = m_directory.get_file(filename);
            std::vector<uint8_t> file_data;
            file_data.reserve(static_cast<size_t>(entry.original_size));
            for (uint64_t i = 0; i < entry.original_size; ++i) {
                file_data.push_back(plain.get_byte(static_cast<size_t>(entry.encrypted_offset + i)));
            }

            std::string out_path = (fs::path(output_dir) / filename).string();
            std::ofstream out_file(out_path, std::ios::binary);
            out_file.write(reinterpret_cast<const char*>(file_data.data()),
                           static_cast<std::streamsize>(file_data.size()));
            out_file.close();
        }
    }
    
    void extract_file(const std::string& filename, const std::string& output_path) {
        auto entry = m_directory.get_file(filename);
        container_t plain;
        plain.copy_from(m_data);
        decrypt_container(plain);

        std::vector<uint8_t> file_data;
        file_data.reserve(static_cast<size_t>(entry.original_size));
        for (uint64_t i = 0; i < entry.original_size; ++i) {
            file_data.push_back(plain.get_byte(static_cast<size_t>(entry.encrypted_offset + i)));
        }

        std::string out_path = output_path.empty() ? filename : output_path;
        std::ofstream out_file(out_path, std::ios::binary);
        out_file.write(reinterpret_cast<const char*>(file_data.data()),
                       static_cast<std::streamsize>(file_data.size()));
        out_file.close();
    }
    
    // ========================================================================
    // Utility Methods
    // ========================================================================
    
    container_t& data() { return m_data; }
    const container_t& data() const { return m_data; }
    DirectoryManager& directory() { return m_directory; }
    const DirectoryManager& directory() const { return m_directory; }
    
    void clear() {
        m_data.clear();
        m_custom_transforms.clear();
        m_mode_stack.clear();
        m_mode_stack.push_back(m_settings.bit_mode);
        m_directory.clear();
        m_pending_files.clear();
        m_current_encrypted_offset = 0;
    }
};

} // namespace genetic_cipher

#endif // GENETIC_CIPHER_HPP
