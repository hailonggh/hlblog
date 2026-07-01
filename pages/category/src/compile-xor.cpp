template <size_t length>
struct compile_time_encrypt
{
    static constexpr char key = 0x30;
    char data[length] = {};

    constexpr compile_time_encrypt(const char (&string)[length])
    {
        for (size_t i = 0; i < length; i++)
        {
            data[i] = string[i] ^ key;
        }
    }

    constexpr compile_time_encrypt<length> xor_decrypt()
    {
        compile_time_encrypt<length> output_string = *this;
        for (size_t i = 0; i < length; i++)
        {
            output_string.data[i] ^= key;
        }
        return output_string;
    }
};

#define _S(string) ([]() {								\
	constexpr compile_time_encrypt en(string);					\
 	return en; }().xor_decrypt().data)

#define _log(format, ...) printf(_S(format), ##__VA_ARGS__)