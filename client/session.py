# Import Communication class from communication module
from communication import Communication

# Import cryptographic functions from mbedtls library
from mbedtls import pk, hmac, hashlib,cipher

class Session:
    # Define RSA key size constant (256 bytes = 2048 bits)
    __RSA_SIZE = 256
    # Define RSA public exponent
    __EXPONENT = 65537
    # Define the secret key for cryptographic operations
    __SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"
