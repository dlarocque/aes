/**
 * Implementation of the encryption and decryption schemes
 * as described in the FIPS 197 document.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"

#define STATE_ROWS 4
#define STATE_COLS 4
#define rc(r, c) ((c * STATE_COLS) + r)
#define BITS_PER_BYTE 8
#define BLOCK_LENGTH 128
#define INPUT_BYTES (BLOCK_LENGTH / BITS_PER_BYTE)
#define NR 10
#define NB 4
#define NK 4

/**
 * Open given plaintext and key files, perform encryption
 * and decryption while printing intermediate results to stdout.
 *
 * @param argc Number of arguments
 * @param argv Arguments
 * @return Success
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Invalid Usage\n");
        return 1;
    }

    // Read input key and plaintext message
    char *plaintext_filename = argv[1];
    char *key_filename = argv[2];
    char raw_plaintext[48] = {0}, raw_key[48] = {0};

    FILE *plaintext_file = fopen(plaintext_filename, "r");
    FILE *key_file = fopen(key_filename, "r");
    if (plaintext_file == NULL || key_file == NULL)
        return -1;

    if (fgets(raw_plaintext, 48, plaintext_file) == NULL)
        return 1;
    if (fgets(raw_key, 48, key_file) == NULL)
        return 1;

    fclose(plaintext_file);
    fclose(key_file);

    uint8_t *m = malloc(BLOCK_LENGTH);
    uint8_t *k = malloc(BLOCK_LENGTH);
    input_to_bytes(raw_plaintext, m);
    input_to_bytes(raw_key, k);

    printf("Plaintext: \n");
    print_byte_array(m, STATE_ROWS * STATE_COLS);
    printf("Key: \n");
    print_byte_array(k, STATE_ROWS * STATE_COLS);

    // Expand the key and print the resulting key schedule
    uint32_t *w = expand(k, rcon);
    printf("Key Schedule\n");
    print_round_keys(w);

    // Encrypt and output intermediate results
    uint8_t *c = encrypt(m, w);

    // Decrypt encrypted cipher text and output intermediate results
    m = decrypt(c, w);

    printf("End of Processing\n");
}

/**
 * Encrypt a plaintext with the AES encryption algorithm.
 *
 * @param m: 128-bit plaintext to be encrypted
 * @param w: Key schedule
 * @return c: Encrypted ciphertext
 */
uint8_t *encrypt(uint8_t *m, uint32_t *w) {
    uint8_t *s = malloc(BLOCK_LENGTH / 8);
    uint8_t *c = malloc(BLOCK_LENGTH / 8);
    memcpy(s, m, INPUT_BYTES);

    printf("ENCRYPTION PROCESS\n------------------\n");
    printf("Plaintext:\n");
    print_state(m);

    add_round_key(s, w, 0);

    for (int i = 1; i < NR; i++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        printf("State after call %d to MixColumns()\n-------------------------------------\n", i);
        print_state(s);
        add_round_key(s, w, i*NB);
    }

    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, w, NR * NB);
 
    memcpy(c, s, INPUT_BYTES);

    printf("Ciphertext: \n");
    print_state(s);
    return c;
}

/**
 * Decrypt a ciphertext using the AES decryption algorithm.
 *
 * @param c: 128-bit ciphertext to be decrypted
 * @param w: Key schedule
 * @return m: Decrypted plaintext
 */
uint8_t *decrypt(uint8_t *c, uint32_t *w) {
    uint8_t *m = malloc(BLOCK_LENGTH / 8);
    uint8_t *s = malloc(BLOCK_LENGTH / 8);
    memcpy(s, c, INPUT_BYTES);

    printf("DECRYPTION PROCESS\n------------------\n");
    printf("Ciphertext:\n");
    print_state(s);

    add_round_key(s, w, NR*NB);

    for (int i = NR-1; i >= 1; i--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, w, i*NB);
        inv_mix_columns(s);
        printf("State after call %d to InvMixColumns()\n-------------------------------------\n", NR-i);
        print_state(s);
    }

    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, w, 0);

    memcpy(m, s, INPUT_BYTES);

    printf("Plaintext: \n");
    print_state(m);
    return m;
}

/**
 * Substitute each byte in the state with the corresponding byte in the
 * substitution box.
 *
 * Instead of using a 2D array for the sbox, and using the hexadecimal format of
 * each byte to access rows and columns, we use a 1D array and access using the decimal numbers.
 *
 * Example:
 * If s[i] = 0x32 = 50, accessing sbox[3][2] in the 2D sbox is equivalent to sbox[50], since
 * sbox[3][2] = sbox[3*16 + 2] = sbox[50].
 *
 * @param s: 128-bit State
 */
void sub_bytes(uint8_t *s) {
    for (int i = 0; i < INPUT_BYTES; i++) {
        s[i] = sbox[s[i]];
    }
}

/**
 * Substitute each byte with the byte at index s[i] in the inv_sbox.
 * See block comment for sub_bytes function to see further explanation.
 *
 * @param s: 128-bit State
 */
void inv_sub_bytes(uint8_t *s) {
    for (int i = 0; i < INPUT_BYTES; i++) {
        s[i] = inv_sbox[s[i]];
    }
}

/**
 * Shift the rows in the state.
 * Row i from 0...3 are shifted right by i columns.
 *
 * @param s: 128-bit State
 */
void shift_rows(uint8_t *s) {
    uint8_t *prev_row = malloc(sizeof(uint8_t) * STATE_COLS);
    for (int r = 1; r < STATE_ROWS; r++) {
        for (int c = 0; c < STATE_COLS; c++) {
            prev_row[c] = s[rc(r, c)];
        }
        for (int c = 0; c < STATE_COLS; c++) {
            s[rc(r, c)] = prev_row[(c + r) % STATE_COLS];
        }
    }
    free(prev_row);
}
/**
 * Inverse the shifting of rows in the state.
 * Row i from 0...3 are shifted left by i columns.
 *
 * @param s: 128-bit State
 */
void inv_shift_rows(uint8_t *s) {
    uint8_t *prev_row = malloc(sizeof(uint8_t) * STATE_COLS);
    for (int r = 1; r < STATE_ROWS; r++) {
        for (int c = 0; c < STATE_COLS; c++) {
            prev_row[c] = s[rc(r, c)];
        }
        for (int c = 0; c < STATE_COLS; c++) {
            s[rc(r, c)] = prev_row[(c - r + STATE_COLS) % STATE_COLS];
        }
    }
    free(prev_row);
}

/**
 * Mix the columns in the state
 * Follows the definition of MixColumns in the FIPS 197 document.
 *
 * Some sort of magic with Galois Fields!
 *
 * @param s: 128-bit State
 */
void mix_columns(uint8_t *s) {
    uint8_t a, b, c, d;
    for (uint8_t i = 0; i < STATE_COLS; i++) {
        a = s[rc(0, i)];
        b = s[rc(1, i)];
        c = s[rc(2, i)];
        d = s[rc(3, i)];
        s[rc(0, i)] = gf_mult(a) ^ gf_mult(b) ^ b ^ c ^ d;
        s[rc(1, i)] = a ^ gf_mult(b) ^ gf_mult(c) ^ c ^ d;
        s[rc(2, i)] = a ^ b ^ gf_mult(c) ^ gf_mult(d) ^ d;
        s[rc(3, i)] = gf_mult(a) ^ a ^ b ^ c ^ gf_mult(d);
    }
}

/**
 * Inverse of the mixing of the columns in the state
 * Follows the definition of InvMixColumns in the FIPS 197 document.
 *
 * Some sort of magic with Galois Fields!
 *
 * @param s: 128-bit State
 */
void inv_mix_columns(uint8_t *s) {
    /*
     * We mix the columns one by one.
     * For each mix, we store the multiplication of each byte in the column in GF(2^8) in the
     * array x.  We store multiplications of each byte in the column from 0x01 through 0x0e.
     *
     * For example, the multiplication of the second byte in the column by 0x0b is stored in
     * x[1][0x0b].
     */
    uint8_t x[4*16]; // {x}, {02 * x}, {04 * x}, {08 * x}, {0xb for all cols
    for (int i = 0; i < STATE_COLS; i++) {
        for (int j = 0; j < 4; j++) {
            // There is likely a nice algorithm for this, but I had issues figuring it out.  Hard-coding it is.
            x[rc(j, 0x01)] = s[rc(j, i)];
            x[rc(j, 0x02)] = gf_mult(x[rc(j, 0x01)]);
            x[rc(j, 0x03)] = x[rc(j, 0x02)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x04)] = gf_mult(x[rc(j, 0x02)]);
            x[rc(j, 0x05)] = x[rc(j, 0x04)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x06)] = gf_mult(x[rc(j, 0x04)]);
            x[rc(j, 0x07)] = x[rc(j, 0x06)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x08)] = gf_mult(x[rc(j, 0x04)]);
            x[rc(j, 0x09)] = x[rc(j, 0x08)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x0a)] = x[rc(j, 0x08)] ^ x[rc(j, 0x02)];
            x[rc(j, 0x0b)] = x[rc(j, 0x08)] ^ x[rc(j, 0x02)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x0c)] = x[rc(j, 0x08)] ^ x[rc(j, 0x04)];
            x[rc(j, 0x0d)] = x[rc(j, 0x08)] ^ x[rc(j, 0x04)] ^ x[rc(j, 0x01)];
            x[rc(j, 0x0e)] = x[rc(j, 0x08)] ^ x[rc(j, 0x04)] ^ x[rc(j, 0x02)];
        }

        s[rc(0, i)] = x[rc(0, 0x0e)] ^ x[rc(1, 0x0b)] ^ x[rc(2, 0x0d)] ^ x[rc(3, 0x09)];
        s[rc(1, i)] = x[rc(0, 0x09)] ^ x[rc(1, 0x0e)] ^ x[rc(2, 0x0b)] ^ x[rc(3, 0x0d)];
        s[rc(2, i)] = x[rc(0, 0x0d)] ^ x[rc(1, 0x09)] ^ x[rc(2, 0x0e)] ^ x[rc(3, 0x0b)];
        s[rc(3, i)] = x[rc(0, 0x0b)] ^ x[rc(1, 0x0d)] ^ x[rc(2, 0x09)] ^ x[rc(3, 0x0e)];
    }
}

/**
 * Rotate the bytes in a 32-bit word left by one.
 *
 * @param w: 32-bit word
 * @return rotated: The rotated 32-bit word
 */
uint32_t rotate_word(uint32_t w) {
    uint32_t rotated = (w << 8)|(w >> (32 - 8));
    return rotated;
}

/**
 * Substitute each byte in a 32-bit word with the corresponding byte
 * in the substitution box.
 *
 * @param w: 32-bit word
 * @return sub: Substituted 32-bit word.
 */
uint32_t sub_word(uint32_t w) {
    uint32_t sub = 0;
    /*
     * We can isolate the byte we want in a word with masking and shifting to LSB.
     * Once we've isolated the bits, we can simply perform a look up in the sbox for
     * the corresponding bytes.  We then shift this substitution right to the original
     * positions of the substituted bits.
     */
    sub |= sbox[(w & 0xff000000) >> 3*8] << 3*8;
    sub |= sbox[(w & 0x00ff0000) >> 2*8] << 2*8;
    sub |= sbox[(w & 0x0000ff00) >> 1*8] << 1*8;
    sub |= sbox[(w & 0x000000ff)];
    return sub;
}

/**
 * Expands a 128-bit key into 11 64-bit keys
 *
 * @param rcon: Round conditions (hard-coded)
 * @return w: Resulting key schedule
 */
uint32_t *expand(const uint8_t *k, const uint32_t *rcon) {
    uint32_t *w = malloc(sizeof(uint32_t) * (NB * (NR+1)));

    for (int i = 0; i < NK; i++) {
        w[i] = 0;
        for (int j = 0; j < 4; j++) {
            w[i] <<= 8;
            w[i] |= k[(NB * i) + j];
        }
    }

    for (int i = NK; i < NB * (NR + 1); i++) {
        uint32_t temp = w[i - 1];
        if (i % NK == 0) {
            temp = sub_word(rotate_word(temp)) ^ rcon[(i / NK) - 1];
        }
        w[i] = w[i-NK] ^ temp;

    }

    return w;
}

/**
 * Add a single round key to the state through a simple XOR.
 *
 * @param s: 128-bit state
 * @param k: Key schedule
 * @param start: Starting index in the key schedule where we find our round key
 */
void add_round_key(uint8_t *s, const uint32_t *k, int start) {
    // Transform the 32-bit array where the round key is stored into an 8-bit round key.
    // This allows us to XOR with the state.
    uint8_t *byte_key = malloc(sizeof(uint8_t) * NB * NB);
    for (int i = 0; i < NB; i++) {
        byte_key[4*i] = (0xff000000 & k[start + i]) >> 3*8;
        byte_key[4*i+1] = (0x00ff0000 & k[start + i]) >> 2*8;
        byte_key[4*i+2] = (0x0000ff00 & k[start + i]) >> 1*8;
        byte_key[4*i+3] = (0x000000ff & k[start + i]);
    }

    for (uint8_t i = 0; i < STATE_ROWS * STATE_COLS; i++) {
        s[i] ^= byte_key[i];
    }
}

uint8_t gf_mult(uint8_t x) {
    uint8_t c = x << 1;
    if (x & 0x80) { // MSB is a 1, so a 1 was shifted out
        return c ^ 0x1b;
    } else {
        return c;
    }
} 

/**
 * Convert the input string (stored in the input files)
 * into a byte array through parsing.
 */
#define INPUT_STR_LEN 48
void input_to_bytes(const char *input, uint8_t *bytes) {
    char str[2] = {0};
    for (int i = 0; i < INPUT_STR_LEN; i++) {
        if ((i + 1) % 3 != 0) {
            str[i % 3] = input[i];
            if ((i + 1) % 3 == 2) {
                bytes[i / 3] = (int) strtol(str, NULL, 16);
            }
        }
    }
}

void print_byte_array(uint8_t *a, int n) {
    for (int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
    printf("\n");
}

void print_state(uint8_t *s) {
    for (int r = 0; r < STATE_ROWS; r++) {
        for (int c = 0; c < STATE_COLS; c++) {
            printf("%02x  ", s[rc(c, r)]);
        }
        printf("  ");
    }
    printf("\n\n");
}

void print_round_keys(uint32_t *w) {
    for (int i = 0; i < NR+1; i++) {
        for (int j = 0; j < NB; j++) {
            printf("%08x", w[(i*NB) + j]);
            if (j < NB-1)
                printf(", ");
        }
        printf("\n");
    }
}
