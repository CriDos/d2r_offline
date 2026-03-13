#include "key_material.hpp"

namespace d2r_offline {
namespace {

constexpr char kOriginalPublicKey[] =
    "-----BEGIN PUBLIC KEY-----\r\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8of3JLclDeK3T0q6l5XL\r\n"
    "4IOHEVTmtMId2fzeUyp9lEx7Gg+gj6QQ4hYZrNdu8PsJk7CiXL/K5yed59zEuJBn\r\n"
    "2F/53twKSQsmoDAINtt8fSKRGbzdWiztr8rXYYc7FuwsCA+SOxPtRZZ/rA+trv3V\r\n"
    "3L0JNmkcwGlu0a5OLDcK+4kWVOp4f5A9VN62CCFCLmdyU6VJ1gUlSVaRUR3wT0eG\r\n"
    "g7EQgFfrDwPgBrtZ3x6K3RDa7hgOZ3+94Qw4qZsfQUBppDR8N/Me2A/n1jJ3JGee\r\n"
    "tdJ/e/pZehpf64ap57xzOLiZkfOexniR5ktcVKAUNn/JGpSrKhry/jeZi8p2Dfet\r\n"
    "3wIDAQAB\r\n"
    "-----END PUBLIC KEY-----\r\n";

constexpr char kReplacementPublicKey[] =
    "-----BEGIN PUBLIC KEY-----\r\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApjIYDKU+559of41ahU9R\r\n"
    "4HN6aZfn10UdirdF93RvJFjEKbX6Ra8TjEjRxkJJi+YdAtm1LxRNx7L5OYLy4F35\r\n"
    "RltLV0LclEDNllOr1U7UV5FoBj3umtf7skB3kqK+kAmMUpcIz6MBvfoF+Zhk9A8l\r\n"
    "aeF6Cs3Yu9v9p6BF8fo+0mZpJdwOUGjFuKpxJtxXCuWpRja5Mzt8LLMs1UQOQd1b\r\n"
    "lsMgIk7ErMxOBftpwQdmNJ3/PNzgJQYw2OhtmhtCMbI5sOIq0J6Be04K2ImAxXao\r\n"
    "/k0feeS+/akGGPvCzu/2EP30ZEdtxucmoq6Qnp5Hp0GgJu//zWWiU2KQt2iXsF0F\r\n"
    "1QIDAQAB\r\n"
    "-----END PUBLIC KEY-----\r\n";

constexpr char kReplacementPrivateKey[] =
    "-----BEGIN PRIVATE KEY-----\r\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmMhgMpT7nn2h/\r\n"
    "jVqFT1Hgc3ppl+fXRR2Kt0X3dG8kWMQptfpFrxOMSNHGQkmL5h0C2bUvFE3Hsvk5\r\n"
    "gvLgXflGW0tXQtyUQM2WU6vVTtRXkWgGPe6a1/uyQHeSor6QCYxSlwjPowG9+gX5\r\n"
    "mGT0DyVp4XoKzdi72/2noEXx+j7SZmkl3A5QaMW4qnEm3FcK5alGNrkzO3wssyzV\r\n"
    "RA5B3VuWwyAiTsSszE4F+2nBB2Y0nf883OAlBjDY6G2aG0Ixsjmw4irQnoF7TgrY\r\n"
    "iYDFdqj+TR955L79qQYY+8LO7/YQ/fRkR23G5yairpCenkenQaAm7//NZaJTYpC3\r\n"
    "aJewXQXVAgMBAAECggEACQ1z+WZb1457iO0YZ+gC5/SqT4uebX+ehRKIDVtKfYKX\r\n"
    "RsVaiUaozCygPooYSvZBEMlugM68kNrbD+ql05pSzGYHI8zoymuAN0a99pu5Xb62\r\n"
    "GZbwgv8uPs6bpMFYG2zlt47yBCtXGjO+9RI7t36GtW56cRG20z6/oYyNmslceCXU\r\n"
    "7l7SyQVO3ds4ECU5ztravBTCUb6xMupI3r/b6C5FG/eoXgUgSgDo6msk+wOf1qXm\r\n"
    "4yN+lg+kEsLwy/N9OWdImkurkKTFu+9dYJNS0XmJm6qHOzeGriLHRaGO1zhaQ797\r\n"
    "fJdJeiRkzF5lboz4bVOc40pzGVa8mcSSmnw1cQRm4QKBgQDOaPCXRmzOWvUp0e0j\r\n"
    "BeD7dk93R3/TM4H2m+NluVuxGSNHNHUPhrdoIXGgwF5ifW9PzCYYzD/CkEZc5yf6\r\n"
    "tWmN7MHs48KetTyvUXcdXC0xg6o8u86w02vcP5ZF6heZsQTm2GpVJJslThTQJpCf\r\n"
    "Bf8kpWH+U4BYlC8qPPIE7G3uoQKBgQDOH9AKkLWtT1LJIBi1+hssNk+bq5WViALh\r\n"
    "2bsdLDdZi3bEbJZBssUIXQx9mifnkPpCk3Mni/ZhM/XpjRU5HVWYz2IjjEWws+Gc\r\n"
    "EwG49lcas+hmzby1GlbhI1PZK2XIByNB7Y3P1OsI3Akw+UCqq56VVHVcsXe2wFqM\r\n"
    "GyIeJIaOtQKBgEWYSm6nFy6oqnr0RiGF7Oq8ZGTSXb4HYu2UeCKnUcwvrp5miIW4\r\n"
    "pYRdqmNKGUjaBDsCmWHJFEJ0xNS0N92nZzSsPGK0FL3QW+q87A2hM7e7Lh4WMMWc\r\n"
    "M4Tqh6+BE34FmqJ/G7MjiZAVeJ0KM776laF0hcrrup2jMRfrvqp8UUChAoGAPqBb\r\n"
    "zVn6WRXoyUL/PwsmhmBZ/6o6YJxag9RrjYmJp6NACp4TaRKv2sKqsN7NkQXzg5bZ\r\n"
    "PgLAcPgglz1OXXQUNcGMx9AuvGlq+sirlU8DWBGhYtrPoxbFntHk/+63lfbVN4q9\r\n"
    "s4+1eZOhF0gj5bcPD8ABiJBDFzuKR1dXHmFqoKECgYEAkrHZTDe5vVQDL5mG1zvf\r\n"
    "agQcI7k2QbW/J8dKbQf/6jGwSY5C1jgqCKhCoWo3kOfOxHDaDs8Hg8UojYj6fOuD\r\n"
    "fzkzBtUW50is504Z0rrT5IFFTr6CozHU0ZVgHpu1kXiNjsGFGTK0hsGTFjdOlHPj\r\n"
    "W2V9/cGG1yAd7aKLAFICUtg=\r\n"
    "-----END PRIVATE KEY-----\r\n";

} // namespace

std::string_view OriginalPublicKeyPem() {
    return kOriginalPublicKey;
}

std::string_view ReplacementPublicKeyPem() {
    return kReplacementPublicKey;
}

std::string_view ReplacementPrivateKeyPem() {
    return kReplacementPrivateKey;
}

} // namespace d2r_offline
