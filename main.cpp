#define DQN_IMPLEMENTATION
#include "Dqn.h"

//
// NOTE: Prototypes
//
// Convert a char string to a binary representation
// bytes: Pass in zero initialised slice that receives the binary representation
// allocator: The allocator to use for allocating bytes
// return: If the conversion was successful
Dqn_b32            Hex_CStringToU8Slice           (char const *hex, Dqn_isize size, Dqn_Slice<Dqn_u8> *bytes, Dqn_Allocator *allocator);
Dqn_b32            Hex_StringToU8Slice            (Dqn_String const string, Dqn_Slice<Dqn_u8> *bytes, Dqn_Allocator *allocator);

// Convert a char string to a binary representation without any checks except assertions in debug.
Dqn_u8            *Hex_CStringToU8Unchecked       (char const *hex, Dqn_isize size, Dqn_isize *real_size, Dqn_Allocator *allocator);
Dqn_Slice<Dqn_u8>  Hex_CStringToU8SliceUnchecked  (char const *hex, Dqn_isize size, Dqn_Allocator *allocator);
Dqn_Slice<Dqn_u8>  Hex_StringToU8SliceUnchecked   (Dqn_String const hex, Dqn_Allocator *allocator);

// Remove whitespace surrounding the string and the 0x prefix if the hex string has it.
// real_size: (Optional) The size of the string after trimming
// return: The start of the string after trimming whitespace and the 0x prefix
char const        *Hex_CStringTrimSpaceAnd0xPrefix(char const *hex, Dqn_isize size, Dqn_isize *real_size);
Dqn_String         Hex_StringTrimSpaceAnd0xPrefix (Dqn_String const string);

// Convert bytes to a hexadecimal string
char              *Hex_U8ToCString                (Dqn_u8 const *bytes, Dqn_isize size, Dqn_Allocator *allocator);
Dqn_String         Hex_U8SliceToString            (Dqn_Slice<Dqn_u8> const bytes, Dqn_Allocator *allocator);

// Convert bytes to a base64 string
Dqn_String         Base64_U8ToString              (Dqn_u8 const *stream, Dqn_isize size, Dqn_Allocator *allocator);

// XOR a slice of bytes with another slice, or with a single byte.
Dqn_Slice<Dqn_u8>  XorU8Slice                     (Dqn_Slice<Dqn_u8> const lhs, Dqn_Slice<Dqn_u8> const rhs, Dqn_Allocator *allocator);
Dqn_Slice<Dqn_u8>  XorU8SliceWithByte             (Dqn_Slice<Dqn_u8> const lhs, char byte, Dqn_Allocator *allocator);

struct SingleKeyXorCipher
{
    float             score;          // Score calculated from English letter frequency
    Dqn_u8            key;            // The key used in this xor decode
    Dqn_Slice<Dqn_u8> decoded_cipher; // The decoded cipher
};

// Brute-force a cipher that using a xor (single byte) key on a ascii hex string in 'hex'
SingleKeyXorCipher SingleKeyXorBestGuess(Dqn_String hex, Dqn_Allocator *allocator);

//
// NOTE: Library Code
//
Dqn_b32 Hex_CStringToU8Slice(char const *hex, Dqn_isize size, Dqn_Slice<Dqn_u8> *bytes, Dqn_Allocator *allocator)
{
    if (bytes) *bytes      = {};
    Dqn_b32     result       = false;
    Dqn_isize   trimmed_size = 0;
    char const *trimmed_hex  = Hex_CStringTrimSpaceAnd0xPrefix(hex, size, &trimmed_size);

    if (trimmed_hex)
    {
        result            = true;
        Dqn_b32 even_size = ((trimmed_size & 1) == 0);
        DQN_ASSERT_MSG(even_size, "Unexpected uneven-size given for converting hex, size: %d, hex: %.*s", trimmed_size, trimmed_size, trimmed_hex);

        if (trimmed_size)
        {
            Dqn_isize bytes_index = 0;
            *bytes = Dqn_Slice_Allocate(allocator, Dqn_u8, (trimmed_size / 2), Dqn_ZeroMem::No);

            for (Dqn_isize trimmed_index = 0; trimmed_index < trimmed_size; trimmed_index += 2)
            {
                char hex01 = trimmed_hex[trimmed_index + 0];
                char hex02 = trimmed_hex[trimmed_index + 1];
                if (Dqn_Char_IsHex(hex01) && Dqn_Char_IsHex(hex02))
                {
                    char value01                 = Dqn_Char_HexToU8(hex01);
                    char value02                 = Dqn_Char_HexToU8(hex02);
                    char value                   = (value01 << 4) | value02;
                    bytes->data[bytes_index++] = value;
                }
                else
                {
                    result = false;
                    break;
                }
            }

            if (result)
            {
                DQN_ASSERT_MSG(bytes->size == bytes_index, "bytes->size=%jd, bytes_index=%jd", bytes->size, bytes_index);
            }
        }
    }

    return result;
}

Dqn_b32 Hex_StringToU8Slice(Dqn_String const string, Dqn_Slice<Dqn_u8> *bytes, Dqn_Allocator *allocator)
{
    Dqn_b32 result = Hex_CStringToU8Slice(string.str, string.size, bytes, allocator);
    return result;
}

Dqn_u8 *Hex_CStringToU8Unchecked(char const *hex, Dqn_isize size, Dqn_isize *real_size, Dqn_Allocator *allocator)
{
    Dqn_u8 *    result       = nullptr;
    Dqn_isize   trimmed_size = 0;
    char const *trimmed_hex  = Hex_CStringTrimSpaceAnd0xPrefix(hex, size, &trimmed_size);

    if (trimmed_size)
    {
        result      = Dqn_Allocator_NewArray(allocator, Dqn_u8, trimmed_size / 2, Dqn_ZeroMem::No);
        Dqn_u8 *ptr = result;

        Dqn_b32 even_size = ((trimmed_size & 1) == 0);
        DQN_ASSERT_MSG(even_size, "Unexpected uneven-size given for converting hex size=%d, hex=%.*s", trimmed_size, trimmed_size, trimmed_hex);

        for (Dqn_isize trimmed_index = 0; trimmed_index < trimmed_size; trimmed_index += 2)
        {
            char hex01 = trimmed_hex[trimmed_index + 0];
            char hex02 = trimmed_hex[trimmed_index + 1];
            DQN_ASSERT_MSG(Dqn_Char_IsHex(hex01), "hex01=%c", hex01);
            DQN_ASSERT_MSG(Dqn_Char_IsHex(hex02), "hex02=%c", hex02);

            char value01 = Dqn_Char_HexToU8(hex01);
            char value02 = Dqn_Char_HexToU8(hex02);
            char value   = (value01 << 4) | value02;
            *ptr++       = value;
        }

        Dqn_u8 const *end = result + trimmed_size / 2;
        DQN_ASSERT_MSG(ptr == end, "ptr: %p, end: %p", ptr, end);
    }

    if (real_size) *real_size = (trimmed_size / 2);
    return result;
}

Dqn_Slice<Dqn_u8> Hex_CStringToU8SliceUnchecked(char const *hex, Dqn_isize size, Dqn_Allocator *allocator)
{
    Dqn_Slice<Dqn_u8> result = {};
    result.data = DQN_CAST(Dqn_u8 *)Hex_CStringToU8Unchecked(hex, size, &result.size, allocator);
    return result;
}

Dqn_Slice<Dqn_u8> Hex_StringToU8SliceUnchecked(Dqn_String const hex, Dqn_Allocator *allocator)
{
    Dqn_Slice<Dqn_u8> result = {};
    result.data = DQN_CAST(Dqn_u8 *)Hex_CStringToU8Unchecked(hex.str, hex.size, &result.size, allocator);
    return result;
}

char const *Hex_CStringTrimSpaceAnd0xPrefix(char const *hex, Dqn_isize size, Dqn_isize *real_size)
{
    Dqn_isize   trimmed_size = 0;
    char const *trimmed_hex  = Dqn_Str_TrimWhitespaceAround(hex, size, &trimmed_size);
    char const *result       = Dqn_Str_TrimPrefix(trimmed_hex,
                                                   trimmed_size,
                                                   "0x",
                                                   2 /*prefix_size*/,
                                                   &trimmed_size);
    if (real_size) *real_size = trimmed_size;
    return result;
}

Dqn_String Hex_StringTrimSpaceAnd0xPrefix(Dqn_String const string)
{
    Dqn_String result = {};
    result.str_       = Hex_CStringTrimSpaceAnd0xPrefix(string.str, string.size, &result.size);
    return result;
}

char *Hex_U8ToCString(char const *bytes, Dqn_isize size, Dqn_Allocator *allocator)
{
    char *result = size > 0 ? Dqn_Allocator_NewArray(allocator, char, size * 2, Dqn_ZeroMem::No) : nullptr;
    if (result)
    {
        char *ptr = result;
        for (Dqn_isize index = 0; index < size; index++)
        {
            char byte  = bytes[index];
            char hex01 = (byte >> 4) & 0xF;
            char hex02 = byte & 0xF;
            DQN_ASSERT_MSG(hex01 <= 0xF, "hex01: %d", hex01);
            DQN_ASSERT_MSG(hex02 <= 0xF, "hex02: %d", hex02);
            *ptr++ = Dqn_Char_ToHexUnchecked(hex01);
            *ptr++ = Dqn_Char_ToHexUnchecked(hex02);
        }
    }

    return result;
}

Dqn_String Hex_U8SliceToString(Dqn_Slice<Dqn_u8> const bytes, Dqn_Allocator *allocator)
{
    Dqn_String result = {};
    result.str        = Hex_U8ToCString(DQN_CAST(char const *)bytes.data, bytes.size, allocator);
    result.size       = bytes.size * 2;
    return result;
}

Dqn_String Base64_U8ToString(Dqn_u8 const *stream, Dqn_isize size, Dqn_Allocator *allocator)
{
    char const BASE64_LUT[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };

    Dqn_isize  total_bits = 8 * size;
    Dqn_String result     = {};

    if (total_bits > 0)
    {
        Dqn_isize bytes_required = (total_bits / 6) + ((total_bits % 6 == 0) ? 0 : 1);
        result                   = Dqn_String_Allocate(allocator, bytes_required, Dqn_ZeroMem::Yes);
        Dqn_isize result_index   = 0;
        int const BYTES_PER_CHUNK = 3;
        for (int stream_offset = 0; stream_offset <= size; stream_offset += BYTES_PER_CHUNK)
        {
            Dqn_b32 can_read_next_3_bytes = (stream_offset + BYTES_PER_CHUNK) <= size;

            Dqn_u8        temp_chunk[BYTES_PER_CHUNK] = {};
            Dqn_u8 const *decode_chunk                = nullptr;

            if (can_read_next_3_bytes)
            {
                decode_chunk = stream + stream_offset;
            }
            else
            {
                // Reading next 3 bytes will read past end of stream so, copy the remainder of the
                // stream to our temp chunk that has sufficient size, then decode that temp chunk.
                Dqn_isize remaining_bytes = size - stream_offset;
                DQN_ASSERT_MSG(remaining_bytes >= 0 && remaining_bytes <= (BYTES_PER_CHUNK - 1), "remaining_bytes=%jd");
                DQN_MEMCOPY(temp_chunk, stream + stream_offset, remaining_bytes);
                decode_chunk = temp_chunk;
            }

            // Every 24 bits (3 bytes) we can read the first (4 x 6bit) sequences and directly
            // convert to base64.
            char bit6_01 =  (decode_chunk[0] & 0b11111100) >> 2;
            char bit6_02 = ((decode_chunk[0] & 0b00000011) << 4 | (decode_chunk[1] & 0b11110000) >> 4);
            char bit6_03 = ((decode_chunk[1] & 0b00001111) << 2 | (decode_chunk[2] & 0b11000000) >> 6);
            char bit6_04 =  (decode_chunk[2] & 0b00111111);

            result.str[result_index++] = BASE64_LUT[DQN_CAST(unsigned)bit6_01];
            result.str[result_index++] = BASE64_LUT[DQN_CAST(unsigned)bit6_02];
            result.str[result_index++] = BASE64_LUT[DQN_CAST(unsigned)bit6_03];
            result.str[result_index++] = BASE64_LUT[DQN_CAST(unsigned)bit6_04];
        }

        // Pad the remainder with '='
        for (; result_index < result.size; result_index++)
            result.str[result_index] = '=';
    }

    return result;
}

Dqn_Slice<Dqn_u8> XorU8Slice(Dqn_Slice<Dqn_u8> const lhs, Dqn_Slice<Dqn_u8> const rhs, Dqn_Allocator *allocator)
{
    Dqn_Slice<Dqn_u8> result = Dqn_Slice_Allocate(allocator, Dqn_u8, lhs.size, Dqn_ZeroMem::No);
    DQN_ASSERT_MSG(lhs.size > 0, "lhs.size=%jd", lhs.size);
    DQN_ASSERT_MSG(lhs.size == rhs.size, "lhs.size=%jd, rhs.size=%jd", lhs.size, rhs.size);
    for (Dqn_isize index = 0; index < lhs.size; index++)
        result.data[index] = (lhs.data[index] ^ rhs.data[index]);
    return result;
}

Dqn_Slice<Dqn_u8> XorU8SliceWithByte(Dqn_Slice<Dqn_u8> const lhs, char byte, Dqn_Allocator *allocator)
{
    Dqn_Slice<Dqn_u8> result = Dqn_Slice_Allocate(allocator, Dqn_u8, lhs.size, Dqn_ZeroMem::No);
    DQN_ASSERT_MSG(lhs.size > 0, "lhs.size=%jd", lhs.size);
    for (Dqn_isize index = 0; index < lhs.size; index++)
        result.data[index] = (lhs.data[index] ^ byte);
    return result;
}

float CalculateXorCipherScore_(Dqn_Slice<Dqn_u8> decoded_cipher)
{
    float letter_frequency[256]         = {};
    letter_frequency[DQN_CAST(int) 'a'] = 0.082f;
    letter_frequency[DQN_CAST(int) 'b'] = 0.015f;
    letter_frequency[DQN_CAST(int) 'c'] = 0.028f;
    letter_frequency[DQN_CAST(int) 'd'] = 0.043f;
    letter_frequency[DQN_CAST(int) 'e'] = 0.013f;
    letter_frequency[DQN_CAST(int) 'f'] = 0.022f;
    letter_frequency[DQN_CAST(int) 'g'] = 0.02f;
    letter_frequency[DQN_CAST(int) 'h'] = 0.061f;
    letter_frequency[DQN_CAST(int) 'i'] = 0.07f;
    letter_frequency[DQN_CAST(int) 'j'] = 0.0015f;
    letter_frequency[DQN_CAST(int) 'k'] = 0.0077f;
    letter_frequency[DQN_CAST(int) 'l'] = 0.04f;
    letter_frequency[DQN_CAST(int) 'm'] = 0.024f;
    letter_frequency[DQN_CAST(int) 'n'] = 0.067f;
    letter_frequency[DQN_CAST(int) 'o'] = 0.075f;
    letter_frequency[DQN_CAST(int) 'p'] = 0.019f;
    letter_frequency[DQN_CAST(int) 'q'] = 0.00095f;
    letter_frequency[DQN_CAST(int) 'r'] = 0.06f;
    letter_frequency[DQN_CAST(int) 's'] = 0.063f;
    letter_frequency[DQN_CAST(int) 't'] = 0.091f;
    letter_frequency[DQN_CAST(int) 'u'] = 0.028f;
    letter_frequency[DQN_CAST(int) 'v'] = 0.0098f;
    letter_frequency[DQN_CAST(int) 'w'] = 0.024f;
    letter_frequency[DQN_CAST(int) 'x'] = 0.0015f;
    letter_frequency[DQN_CAST(int) 'y'] = 0.02f;
    letter_frequency[DQN_CAST(int) 'z'] = 0.00074f;
    letter_frequency[DQN_CAST(int) ' '] = 0.010f; // NOTE: I randomly gave this a weight

    float result = 0;
    for (Dqn_u8 byte : decoded_cipher)
        result += letter_frequency[DQN_CAST(int) byte];
    return result;
}

SingleKeyXorCipher SingleKeyXorBestGuess(Dqn_String hex, Dqn_Allocator *allocator)
{
    Dqn_u8 const            KEY_SIZE = 255;
    SingleKeyXorCipher      result   = {};
    Dqn_Slice<Dqn_u8> const cipher   = Hex_StringToU8SliceUnchecked(hex, allocator);

    for (Dqn_u16 key = 0; key < KEY_SIZE; key++)
    {
        Dqn_Slice<Dqn_u8>  xor_slice  = XorU8SliceWithByte(cipher, DQN_CAST(char) key, allocator);
        SingleKeyXorCipher xor_cipher = {};
        xor_cipher.decoded_cipher     = xor_slice;
        xor_cipher.score              = CalculateXorCipherScore_(xor_slice);
        xor_cipher.key                = DQN_CAST(char)key;
        if (xor_cipher.score > result.score)
            result = xor_cipher;
    }

    return result;
}

//
// NOTE: Cryptopals Code
//
Dqn_ArenaAllocator g_arena = Dqn_ArenaAllocator_InitWithNewAllocator(Dqn_Allocator_InitWithHeap(), 0, nullptr);
Dqn_Allocator g_allocator  = Dqn_Allocator_InitWithArena(&g_arena);

void Cryptopals_Set01_Challenge01()
{
    Dqn_String const hex             = DQN_STRING("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    Dqn_Slice<Dqn_u8> const bytes    = Hex_StringToU8SliceUnchecked(hex, &g_allocator);
    Dqn_String const base64          = Base64_U8ToString(bytes.data, bytes.size, &g_allocator);
    Dqn_String const expected_base64 = DQN_STRING("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    DQN_LOG_I("[Challenge 1]");
    DQN_LOG_I("hex    = %.*s", DQN_STRING_FMT(hex));
    DQN_LOG_I("base64 = %.*s\n", DQN_STRING_FMT(base64));

    DQN_ASSERT(base64.size == expected_base64.size);
    DQN_ASSERT_MSG(base64 == expected_base64, "base64=%.*s, expected_base64=%.*s", DQN_STRING_FMT(base64), DQN_STRING_FMT(expected_base64));
}

void Cryptopals_Set01_Challenge02()
{
    Dqn_String const lhs_hex      = DQN_STRING("1c0111001f010100061a024b53535009181c");
    Dqn_String const rhs_hex      = DQN_STRING("686974207468652062756c6c277320657965");
    Dqn_String const expected_hex = DQN_STRING("746865206b696420646f6e277420706c6179");

    Dqn_Slice<Dqn_u8> const lhs_bytes      = Hex_StringToU8SliceUnchecked(lhs_hex, &g_allocator);
    Dqn_Slice<Dqn_u8> const rhs_bytes      = Hex_StringToU8SliceUnchecked(rhs_hex, &g_allocator);
    Dqn_Slice<Dqn_u8> const expected_bytes = Hex_StringToU8SliceUnchecked(expected_hex, &g_allocator);

    Dqn_Slice<Dqn_u8> result     = XorU8Slice(lhs_bytes, rhs_bytes, &g_allocator);
    Dqn_String        result_hex = Hex_U8SliceToString(result, &g_allocator);

    DQN_LOG_I("[Challenge 2]");
    DQN_LOG_I("result   = %.*s", DQN_STRING_FMT(result_hex));
    DQN_LOG_I("expected = %.*s\n", DQN_STRING_FMT(expected_hex));

    DQN_ASSERT_MSG(result.size == expected_bytes.size,
                   "result.size=%jd, expected_bytes.size=%jd",
                   result.size,
                   expected_bytes.size);

    DQN_ASSERT_MSG(DQN_MEMCMP(expected_bytes.data, result.data, result.size) == 0,
                   "expected_bytes=%.*x, result.str=%.*x",
                   DQN_SLICE_FMT(expected_bytes),
                   DQN_SLICE_FMT(expected_bytes));
}

void Cryptopals_Set01_Challenge03()
{
    Dqn_String const CIPHER_TEXT  = DQN_STRING("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    SingleKeyXorCipher xor_cipher = SingleKeyXorBestGuess(CIPHER_TEXT, &g_allocator);

    DQN_LOG_I("[Challenge 3]");
    DQN_LOG_I("input       = %.*s", DQN_STRING_FMT(CIPHER_TEXT));
    DQN_LOG_I("xor key     = %c (%d)", xor_cipher.key, xor_cipher.key);
    DQN_LOG_I("cipher text = %.*s\n", DQN_SLICE_FMT(xor_cipher.decoded_cipher));
}

void Cryptopals_Set01_Challenge04()
{
    Dqn_String file = {};
    file.str        = Dqn_File_ReadEntireFile("set01-challenge04.txt", &file.size, &g_allocator);

    Dqn_Slice<Dqn_String> strings         = Dqn_String_Split(file, &g_allocator);
    SingleKeyXorCipher    best_xor_cipher = {};
    Dqn_String            cipher          = {};
    for (Dqn_String line : strings)
    {
        SingleKeyXorCipher xor_cipher = SingleKeyXorBestGuess(line, &g_allocator);
        if (xor_cipher.score > best_xor_cipher.score)
        {
            best_xor_cipher = xor_cipher;
            cipher          = line;
        }
    }

    DQN_LOG_I("[Challenge 4]");
    DQN_LOG_I("input       = %.*s", DQN_STRING_FMT(cipher));
    DQN_LOG_I("xor key     = %c (%d)", best_xor_cipher.key, best_xor_cipher.key);
    DQN_LOG_I("cipher text = %.*s", DQN_SLICE_FMT(best_xor_cipher.decoded_cipher));
}

int main()
{
    auto mem_scope = Dqn_ArenaAllocator_MakeScopedRegion(&g_arena);
    {
        Dqn_Slice<Dqn_u8> bytes = Hex_StringToU8SliceUnchecked(DQN_STRING(" 0x0F "), &g_allocator);
        DQN_ASSERT_MSG(bytes.data[0] == 0x0f, "bytes.data[0]=%d", bytes.data[0]);
        DQN_ASSERT_MSG(bytes.size == 1, "bytes.size=%jd", bytes.size);
    }

    {
        Dqn_Slice<Dqn_u8> bytes = Hex_StringToU8SliceUnchecked(DQN_STRING(" 0xaF "), &g_allocator);
        DQN_ASSERT_MSG(bytes.data[0] == 0xaf, "bytes.data[0]=%d", bytes.data[0]);
        DQN_ASSERT_MSG(bytes.size == 1, "bytes.size=%jd", bytes.size);
    }

    {
        char const *result = Hex_U8ToCString("\x1", 1, &g_allocator);
        DQN_ASSERT_MSG(result[0] == '0', "result[0]=%c", result[0]);
        DQN_ASSERT_MSG(result[1] == '1', "result[1]=%c", result[1]);
    }

    {
        char const *result = Hex_U8ToCString("\xA", 1, &g_allocator);
        DQN_ASSERT_MSG(result[0] == '0', "result[0]=%c", result[0]);
        DQN_ASSERT_MSG(result[1] == 'a', "result[1]=%c", result[1]);
    }

    Cryptopals_Set01_Challenge01();
    Cryptopals_Set01_Challenge02();
    Cryptopals_Set01_Challenge03();
    Cryptopals_Set01_Challenge04();

    Dqn_ArenaAllocator_DumpStatsToLog(&g_arena, "Global Arena");
    return 0;
}
