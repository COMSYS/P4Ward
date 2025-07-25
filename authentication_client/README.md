# Authentication Client

The authentication client implements the two authentication procedures we currently support, which are EAP-MD5 and EAP-OTP. The parsing and deparsing of network packets are defined in the `auth-headers.c` and `auth-headers.h` files. The final logic for performing the authentication is located in the main `auth.c` file. To compile the authentication client simply generates the project using cmake:

```bash
mkdir build
cd build
cmake ..
make
```

# Features

To simplify the evaluation process our authentication client packs a few key features:
- Support for reauthentication
- Disable reauthentication flag to log off immediately after authentication
- Predefined cutoff to automatically log off after a certain number of authentications/reauthentications