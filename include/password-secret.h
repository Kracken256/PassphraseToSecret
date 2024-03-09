#ifndef __PASSWORD_SECRET_H__
#define __PASSWORD_SECRET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>

#ifndef OUT
#define OUT
#endif

/// @brief Includes the NULL terminator
#define MNEONIC_MAX_LENGTH 36

    /// @brief Convert a 4 word BIP39 mnemonic to a 8 byte key
    /// @param mnemonic The 4 word BIP39 mnemonic
    /// @param key The 8 byte key
    /// @return true if the mnemonic is valid, false otherwise
    /// @warning Don't forget to check the return value. Invalid mnemonics leave the key buffer unchanged.
    bool pwsec_derivebytes(const char *mnemonic, OUT uint8_t key[6]);

    /// @brief Convert an 8 byte key to a 4 word BIP39 mnemonic
    /// @param key The 8 byte key
    /// @param mnemonic NULL terminated string containing the 4 word BIP39 mnemonic
    void pwsec_mnemonic(const uint8_t key[6], OUT char mnemonic[MNEONIC_MAX_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif // __PASSWORD_SECRET_H__
