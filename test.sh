# A minimal test harness for the p11-kit OpenSSL engine

# Requires:
# * an actual token to work with PAP (accepts empty password)
#   GNOME Keyring works well
# * GnuTLS
#   Provides p11tool to manipulate the token

TOKEN='pkcs11:model=1.0;manufacturer=Gnome%20Keyring;serial=1%3aUSER%3aDEFAULT;token=Gnome2%20Key%20Storage'
PRIVKEY=test.key

# Pre-test fixture clean up
rm -f test issue test.key
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Generate a test key
openssl genrsa >test.key

# Load the private key to the token
p11tool --batch --login --label=Test-Server --write --load-privkey=test.key "$TOKEN"

# Perform encryption
openssl <<EOF
engine -t -pre SO_PATH:$PWD/.libs/libp11-kit-engine.so -pre LIST_ADD:1 -pre LOAD dynamic
rsautl -engine pkcs11 -keyform engine -encrypt -inkey '$TOKEN;object=Test-Server;type=private;pin-value=' -in /etc/issue -out $PWD/test
EOF

# Drop the object from the token
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Decrypt with the default RSA engine
openssl \
rsautl -decrypt -inkey test.key -in test -out issue

# Check if the files are different
diff /etc/issue issue

# Cleanup
rm -f test issue test.key
