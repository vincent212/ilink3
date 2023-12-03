// using Crypto++ library version 5.6.5 from https://www.cryptopp.com/

#include <string>
#include <cstdlib>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"

static std::string calculateHMAC(const std::string &key, const std::string &canonicalRequest, bool debug = false)
{

    std::string decoded_key, calculatedHmac, encodedHmac;

    if (debug)
    {
        std::cerr << "key: " << key << std::endl;
        std::cerr << "canonicalRequest: " << canonicalRequest << std::endl;
    }

    try
    {
        // Decode the key since it is base64url encoded
        CryptoPP::StringSource(key, true,
                               new CryptoPP::Base64URLDecoder(
                                   new CryptoPP::StringSink(decoded_key)) // Base64URLDecoder
        );                                                                // StringSource

        // Calculate HMAC
        CryptoPP::HMAC<CryptoPP::SHA256> hmac((byte *)decoded_key.c_str(), decoded_key.size());

        CryptoPP::StringSource(canonicalRequest, true,
                               new CryptoPP::HashFilter(hmac,
                                                        new CryptoPP::StringSink(calculatedHmac)) // HashFilter
        );                                                                                        // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        abort();
    }

    if (debug)
    {
        std::cerr << "encodedHmac: " << encodedHmac << std::endl;
        std::cerr << "encodedHmac.size(): " << encodedHmac.size() << std::endl;
        std::cerr << "calculatedHmac: " << calculatedHmac << std::endl;
        std::cerr << "calculatedHmac.size(): " << calculatedHmac.size() << std::endl;
    }

    return calculatedHmac;
}
