#include <iostream>
#include <cmath>
#include <openssl/evp.h>

using namespace std;
//                                    11111111112222222
//                           12345678901234567890123456
static const string alpha = "abcdefghijklmnopqrstuvwxyz";

string caesar(const std::string& plain,
              int shift) {
    string result;
    for (const auto& c: plain) {
        if (c == ' ') {
            result += " ";
            continue;
        };
        size_t i = c - 97;
        size_t j = (i + shift) % alpha.size();
        result += alpha[j];
    }
    return result;
}

string caesar_dec(const std::string& cipher,
                  int shift) {
    string result;
    for (const auto& c: cipher) {
        if (c == ' ') {
            result += " ";
            continue;
        };
        size_t i = 26 + c - 97;
        size_t j = (i - shift) % alpha.size();
        result += alpha[j];
    }
    return result;
}

string vigener_enc(const std::string& plain,
                   const std::string& key) {
    string result = "";
    for (size_t i = 0; i < plain.size(); ++i) {
        size_t c = plain[i] - 97;
        size_t k = key[i % key.size()] - 97;
        result += alpha[(c + k + 1) % 26];
    }
    return result;
}

string vigener_dec(const std::string& cipher,
                   const std::string& key) {
    string result = "";
    for (size_t i = 0; i < cipher.size(); ++i) {
        size_t c = 26 + cipher[i] - 97;
        size_t k = key[i % key.size()] - 97;
        result += alpha[(c - k - 1) % 26];
    }
    return result;

}

string base64_enc(const string& plain) {
    size_t size = 4 * (plain.size() + 2) / 3;
    u_char cipher[size + 1];
    const u_char* input = reinterpret_cast<const u_char*>(plain.c_str());
    EVP_EncodeBlock(cipher, input, plain.size());
    return string(reinterpret_cast<char*>(cipher));
}

string base64_dec(const string& cipher) {
    size_t size = 3 * cipher.size() / 4;
    u_char plain[size + 1];
    const u_char* input = reinterpret_cast<const u_char*>(cipher.c_str());
    EVP_DecodeBlock(plain, input, cipher.size());
    return string(reinterpret_cast<char*>(plain));
}

int main() {
    cout << "CRYPTOGRAPHY\n";
    cout << "- Caesar\n";
    cout << "[+] plain: ahz shift: 2 cipher: " << caesar("ahz", 2) << '\n';
    cout << "[+] cipher: " << caesar("ahz", 2)
         << " shift: 2 plain: " << caesar_dec(caesar("ahz", 2), 2) << '\n';
    cout << "- Vigener\n";
    cout << "[+] plain: whatanicedaytoday key: crypto cipher: "
         << vigener_enc("whatanicedaytoday", "crypto") << '\n';
    cout << "[+] cipher: " << vigener_enc("whatanicedaytoday", "crypto")
         << " key: crypto plain: " << vigener_dec(vigener_enc("whatanicedaytoday", "crypto"), "crypto") << '\n';
    cout << "- Base64 (openssl)\n";
    cout << "[+] plain: hello crypto world cipher: " << base64_enc("hello world") << '\n';
    cout << "[+] cipher: " << base64_enc("hello world") << " plain: "
         << base64_dec(base64_enc("hello world")) << '\n';
    return 0;
}
