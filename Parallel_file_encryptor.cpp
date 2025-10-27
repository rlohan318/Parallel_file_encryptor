// parallel_file_encryptor.cpp
// Build: g++ -std=c++17 parallel_file_encryptor.cpp -lcrypto -pthread -O2 -o pfe
// Usage:
//  Encrypt: ./pfe encrypt input.bin output.pfe password [threads] [chunk-size-bytes]
//  Decrypt: ./pfe decrypt input.pfe output.bin password [threads]
//
// Notes:
//  - Default threads = hardware_concurrency() or 4
//  - Default chunk size = 4*1024*1024 (4 MiB)
//  - File format (header):
//      4 bytes magic "PFE1"
//      1 byte version (0x01)
//      16 bytes salt (PBKDF2 salt)
//      16 bytes nonce (initial nonce prefix for CTR, 128-bit total IV; we'll use structure nonce || counter)
//      8 bytes original file size (uint64_t little-endian)
//

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <atomic>

using byte = unsigned char;

static void handleOpenSSLErrors(const char* msg) {
    std::cerr << msg << "\n";
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

static uint64_t to_uint64_le(uint64_t v){
    uint64_t out = v;
    // assume little-endian host (common); convert explicitly for portability
    byte *p = reinterpret_cast<byte*>(&out);
    return out;
}

bool derive_key_from_password(const std::string &password, const std::vector<byte>& salt, std::vector<byte>& key_out, int iterations = 200000) {
    key_out.assign(32, 0);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                           salt.data(), (int)salt.size(),
                           iterations,
                           EVP_sha256(),
                           (int)key_out.size(), key_out.data())) {
        return false;
    }
    return true;
}

// increment little-endian 128-bit counter stored in iv (16 bytes).
void add_counter_to_iv(std::vector<byte>& iv, uint64_t counter) {
    // treat last 8 bytes of iv as big-endian or little? We'll use little-endian increment at offset 8-15.
    // We'll add counter to iv[8..15] as little-endian.
    uint64_t carry = counter;
    for (int i = 15; i >= 8 && carry; --i) {
        uint64_t sum = (uint64_t)iv[i] + (carry & 0xFF);
        iv[i] = (byte)(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
    }
    // Note: this simplistic carry handling is acceptable for counters that fit in 64-bit.
}

bool aes256_ctr_crypt(const std::vector<byte>& key, const std::vector<byte>& iv, const byte* in, size_t inlen, std::vector<byte>& out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    if(1 != EVP_CIPHER_CTX_set_key_length(ctx, (int)key.size())) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }

    out.assign(inlen, 0);
    int outlen1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, out.data(), &outlen1, in, (int)inlen)) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int outlen2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.data()+outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    // total outlen should be outlen1 + outlen2 == inlen for CTR
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

struct ChunkTask {
    size_t index;
    size_t offset;
    size_t size;
};

int main(int argc, char** argv) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (argc < 5) {
        std::cout << "Usage:\n  Encrypt: " << argv[0] << " encrypt input output password [threads] [chunk_size]\n";
        std::cout << "  Decrypt: " << argv[0] << " decrypt input output password [threads]\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string infile = argv[2];
    std::string outfile = argv[3];
    std::string password = argv[4];

    unsigned int threads = std::max(1u, std::thread::hardware_concurrency());
    size_t chunk_size = 4ull * 1024 * 1024; // 4 MiB

    if (argc >= 6) threads = std::max(1u, (unsigned int)std::stoul(argv[5]));
    if (argc >= 7) chunk_size = std::stoull(argv[6]);

    std::ifstream fin(infile, std::ios::binary);
    if (!fin) {
        std::cerr << "Cannot open input file\n";
        return 2;
    }
    fin.seekg(0, std::ios::end);
    uint64_t filesize = (uint64_t)fin.tellg();
    fin.seekg(0);

    if (mode == "encrypt") {
        // Prepare header
        const char magic[4] = {'P','F','E','1'};
        const uint8_t version = 0x01;
        std::vector<byte> salt(16);
        std::vector<byte> nonce(16); // full 128-bit IV template; we'll treat nonce + counter
        if (1 != RAND_bytes(salt.data(), (int)salt.size())) handleOpenSSLErrors("RAND_bytes failed for salt");
        if (1 != RAND_bytes(nonce.data(), (int)nonce.size())) handleOpenSSLErrors("RAND_bytes failed for nonce");

        std::vector<byte> key;
        if (!derive_key_from_password(password, salt, key)) handleOpenSSLErrors("Key derivation failed");

        // prepare chunks
        size_t nchunks = (filesize + chunk_size - 1) / chunk_size;
        std::vector<ChunkTask> tasks;
        tasks.reserve(nchunks);
        for (size_t i = 0; i < nchunks; ++i) {
            size_t off = i * chunk_size;
            size_t sz = (size_t)std::min<uint64_t>(chunk_size, filesize - off);
            tasks.push_back({(size_t)i, (size_t)off, sz});
        }

        // read all chunks and encrypt in parallel into buffers
        std::vector<std::vector<byte>> outputs(nchunks);
        std::atomic<size_t> next_task(0);

        auto worker = [&](unsigned int tid){
            while (true) {
                size_t idx = next_task.fetch_add(1);
                if (idx >= tasks.size()) break;
                auto &t = tasks[idx];

                // read chunk
                std::vector<byte> inbuf(t.size);
                {
                    std::lock_guard<std::mutex> lg(*(new std::mutex())); // local dummy to avoid data race on fin reading - we'll instead read using separate ifstream
                    // simpler: open and read chunk with its own ifstream to avoid global lock
                }
                std::ifstream fin2(infile, std::ios::binary);
                fin2.seekg((std::streamoff)t.offset);
                fin2.read(reinterpret_cast<char*>(inbuf.data()), (std::streamsize)t.size);
                fin2.close();

                // prepare IV for this chunk: nonce with counter = chunk_index * (chunk_size / AES_block)
                std::vector<byte> iv = nonce;
                // counter = number of 16-byte blocks offset for this chunk
                uint64_t blocks_before = (t.offset) / 16;
                add_counter_to_iv(iv, blocks_before);

                // encrypt
                std::vector<byte> outbuf;
                if (!aes256_ctr_crypt(key, iv, inbuf.data(), inbuf.size(), outbuf)) {
                    std::cerr << "Encryption failed for chunk " << t.index << "\n";
                    std::exit(1);
                }
                outputs[t.index].swap(outbuf);
            }
        };

        // spawn threads
        std::vector<std::thread> pool;
        for (unsigned int i=0;i<threads;i++) pool.emplace_back(worker, i);
        for (auto &th: pool) th.join();

        // write output file: header + all encrypted chunks in order
        std::ofstream fout(outfile, std::ios::binary);
        if (!fout) {
            std::cerr << "Cannot open output file for writing\n"; return 3;
        }
        fout.write(magic, 4);
        fout.put((char)version);
        fout.write(reinterpret_cast<char*>(salt.data()), salt.size());
        fout.write(reinterpret_cast<char*>(nonce.data()), nonce.size());
        uint64_t fs_le = filesize;
        fout.write(reinterpret_cast<char*>(&fs_le), sizeof(fs_le));
        // now write chunks sequentially
        for (size_t i=0;i<nchunks;i++){
            fout.write(reinterpret_cast<char*>(outputs[i].data()), (std::streamsize)outputs[i].size());
        }
        fout.close();
        std::cout << "Encryption complete. File: " << outfile << "\n";
    }
    else if (mode == "decrypt") {
        std::ifstream fin2(infile, std::ios::binary);
        if (!fin2) { std::cerr << "Cannot open encrypted file\n"; return 2; }
        char magic[4];
        fin2.read(magic, 4);
        if (std::memcmp(magic, "PFE1", 4) != 0) { std::cerr << "Bad file format\n"; return 4; }
        uint8_t version;
        fin2.read(reinterpret_cast<char*>(&version), 1);
        if (version != 0x01) { std::cerr << "Unsupported version\n"; return 5; }
        std::vector<byte> salt(16), nonce(16);
        fin2.read(reinterpret_cast<char*>(salt.data()), salt.size());
        fin2.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
        uint64_t orig_size;
        fin2.read(reinterpret_cast<char*>(&orig_size), sizeof(orig_size));

        // derive key
        std::vector<byte> key;
        if (!derive_key_from_password(password, salt, key)) handleOpenSSLErrors("Key derivation failed");

        // remaining bytes are encrypted stream
        fin2.seekg(0, std::ios::end);
        std::streamoff enc_size = fin2.tellg() - (4 + 1 + (std::streamoff)salt.size() + (std::streamoff)nonce.size() + (std::streamoff)sizeof(orig_size));
        fin2.seekg(4 + 1 + (std::streamoff)salt.size() + (std::streamoff)nonce.size() + (std::streamoff)sizeof(orig_size));
        size_t nchunks = (size_t)((enc_size + chunk_size - 1) / chunk_size);
        std::vector<ChunkTask> tasks;
        tasks.reserve(nchunks);
        for (size_t i = 0; i < nchunks; ++i) {
            size_t off = i * chunk_size;
            size_t sz = (size_t)std::min<uint64_t>(chunk_size, (uint64_t)enc_size - off);
            tasks.push_back({(size_t)i, (size_t)(4 + 1 + salt.size() + nonce.size() + sizeof(orig_size) + off), sz});
        }
        std::vector<std::vector<byte>> outputs(nchunks);
        std::atomic<size_t> next_task(0);

        auto worker = [&](unsigned int tid){
            while (true) {
                size_t idx = next_task.fetch_add(1);
                if (idx >= tasks.size()) break;
                auto &t = tasks[idx];
                // read encrypted chunk
                std::vector<byte> inbuf(t.size);
                std::ifstream fin3(infile, std::ios::binary);
                fin3.seekg((std::streamoff)t.offset);
                fin3.read(reinterpret_cast<char*>(inbuf.data()), (std::streamsize)t.size);
                fin3.close();

                // prepare iv with counter offset
                std::vector<byte> iv = nonce;
                uint64_t blocks_before = (t.index * (uint64_t)chunk_size) / 16;
                add_counter_to_iv(iv, blocks_before);

                // decrypt (CTR: same operation)
                std::vector<byte> outbuf;
                if (!aes256_ctr_crypt(key, iv, inbuf.data(), inbuf.size(), outbuf)) {
                    std::cerr << "Decryption failed for chunk " << t.index << "\n";
                    std::exit(1);
                }
                // If it's the final chunk, trim to original file size
                outputs[t.index].swap(outbuf);
            }
        };

        // spawn threads
        std::vector<std::thread> pool;
        for (unsigned int i=0;i<threads;i++) pool.emplace_back(worker, i);
        for (auto &th: pool) th.join();

        // write final file (trim last chunk)
        std::ofstream fout(outfile, std::ios::binary);
        if (!fout) { std::cerr << "Cannot open output file\n"; return 6; }
        uint64_t written = 0;
        for (size_t i=0;i<nchunks;i++){
            size_t to_write = outputs[i].size();
            if (written + to_write > orig_size) {
                to_write = (size_t)(orig_size - written);
            }
            fout.write(reinterpret_cast<char*>(outputs[i].data()), (std::streamsize)to_write);
            written += to_write;
            if (written >= orig_size) break;
        }
        fout.close();
        std::cout << "Decryption complete. File: " << outfile << "\n";
    }
    else {
        std::cerr << "Unknown mode (encrypt/decrypt)\n";
        return 1;
    }

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
