#include <password-secret.h>
#include <stdio.h>
#include <string.h>

static void print_help(const char *program)
{
    printf("Usage: echo <mnemonic|hexkey> | %s [-e|-d]\n", program);
}

static int encode()
{
    union
    {
        char hexkey[13];
        char mnemonic[MNEONIC_MAX_LENGTH];
    } u;
    uint8_t key[6];

    // read hexkey from stdin
    if (fgets(u.hexkey, sizeof(u.hexkey), stdin) == NULL)
    {
        fprintf(stderr, "Error reading hexkey from stdin\n");
        return 1;
    }

    u.hexkey[12] = '\0'; // remove newline

    // decode hexkey
    for (int i = 0; i < 6; i++)
    {
        if (sscanf(u.hexkey + 2 * i, "%2hhx", &key[i]) != 1)
        {
            fprintf(stderr, "Error encoding hexkey\n");
            return 1;
        }
    }

    // encode mnemonic
    pwsec_mnemonic(key, u.mnemonic);
    printf("%s\n", u.mnemonic);

    return 0;
}

static int decode()
{
    union
    {
        char hexkey[12];
        char mnemonic[MNEONIC_MAX_LENGTH];
    } u;
    uint8_t key[6];

    // read mnemonic from stdin
    if (fgets(u.mnemonic, sizeof(u.mnemonic), stdin) == NULL)
    {
        fprintf(stderr, "Error reading mnemonic from stdin\n");
        return 1;
    }

    // decode mnemonic
    if (!pwsec_derivebytes(u.mnemonic, key))
    {
        fprintf(stderr, "Error decoding mnemonic\n");
        return 1;
    }

    // encode hexkey
    for (int i = 0; i < 6; i++)
    {
        sprintf(u.hexkey + 2 * i, "%02x", key[i]);
    }
    printf("%s\n", u.hexkey);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        print_help(argv[0]);
        return 1;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "-e") == 0)
    {
        return encode();
    }
    else if (strcmp(mode, "-d") == 0)
    {
        return decode();
    }
    else
    {
        print_help(argv[0]);
        return 1;
    }
}
