import ctypes, os
L = ctypes.CDLL('/usr/lib/libcompression.dylib')
L.compression_encode_buffer.restype = ctypes.c_size_t
L.compression_decode_buffer.restype = ctypes.c_size_t
L.compression_encode_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
L.compression_decode_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
M = 0xE05
def enc(b, alg=M):
    o = ctypes.create_string_buffer(len(b) * 2 + 4096)
    n = L.compression_encode_buffer(o, len(o), b, len(b), None, alg)
    return o.raw[:n]
def dec(c, cap, alg=M):
    o = ctypes.create_string_buffer(cap + 64)
    n = L.compression_decode_buffer(o, cap + 64, c, len(c), None, alg)
    return o.raw[:n]
