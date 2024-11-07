import zlib


def compress_string(input_string):
    # Convert the input string to bytes
    input_bytes = input_string.encode('utf-8')

    # Compress the bytes using zlib
    compressed_bytes = zlib.compress(input_bytes)

    # Convert the compressed bytes to a string using base64 encoding
    compressed_string = compressed_bytes.hex()

    return compressed_string


def decompress_string(compressed_string):
    # Convert the base64 encoded string back to bytes
    compressed_bytes = bytes.fromhex(compressed_string)

    # Decompress the bytes using zlib
    decompressed_bytes = zlib.decompress(compressed_bytes)

    # Convert the decompressed bytes back to a string
    decompressed_string = decompressed_bytes.decode('utf-8')

    return decompressed_string