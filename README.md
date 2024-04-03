# Unwrap yubihsm wrapped keys

Usage:

    java -jar yubikey-unwrap.jar <public-key-file> <wrapped-key-file> <wrapping-key-file> [output-key-file]

Where:
- `public-key` is the public key or certificate associated with the wrapped key (PEM format)
- `wrapped-key` is the wrapped blob in base64
- `wrapping-key` is the wrapping key (hex)
- `output-key` is the output key file (optional, pem)

Password during export is optional