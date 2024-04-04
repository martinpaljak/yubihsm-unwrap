# Unwrap yubihsm wrapped keys

Usage:

    java -jar yubihsm-unwrap.jar <wrapped-key-file> <wrapping-key-file> [output-key-file]

Where:
- `wrapped-key` is the wrapped blob in base64
- `wrapping-key` is the wrapping key (hex)
- `output-key` is the output key file (optional, pem)

Password during export is optional.

This is the reverse of what [yhwrap](https://github.com/Yubico/yubihsm-shell/tree/master/yhwrap) utility does.
