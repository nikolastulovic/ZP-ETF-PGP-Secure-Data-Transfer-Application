import base64


def convert_to_radix64(input_string):
    # Convert the input string to bytes
    input_bytes = input_string.encode('utf-8')

    # Encode the bytes to Base64
    base64_bytes = base64.b64encode(input_bytes)

    # Convert the Base64 bytes to a string
    base64_string = base64_bytes.decode('utf-8')

    return base64_string


def decode_from_radix64(base64_string):
    # Convert the Base64 string to bytes
    base64_bytes = base64_string.encode('utf-8')

    # Decode the Base64 bytes
    decoded_bytes = base64.b64decode(base64_bytes)

    # Convert the decoded bytes back to a string
    decoded_string = decoded_bytes.decode('utf-8')

    return decoded_string
