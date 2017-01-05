# A minimal test harness for the p11-kit OpenSSL engine

# Requires:
# * an actual token to work with PAP (accepts empty password)
#   GNOME Keyring works swll
# * a RSA private key
#   OpenVPN samples are fine
# * GnuTLS
#   Provides p11tool to manipulate the token

TOKEN='pkcs11:model=1.0;manufacturer=Gnome%20Keyring;serial=1%3aUSER%3aDEFAULT;token=Gnome2%20Key%20Storage'
PRIVKEY='/usr/share/doc/openvpn/sample/sample-keys/server.key'

# Pre-test fixture clean up
rm -f test issue
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Load the private key to the token
p11tool --batch --login --label=Test-Server --write --load-privkey=$PRIVKEY "$TOKEN"

# Perform encryption
openssl <<EOF
engine -t dynamic -pre SO_PATH:$PWD/.libs/libp11-kit.so -pre LIST_ADD:1 -pre LOAD
rsautl -engine p11-kit -keyform engine -encrypt -inkey '$TOKEN;object=Test-Server;type=private;pin-value=' -in /etc/issue -out $PWD/test
EOF

# Drop the object from the token
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Decrypt with the default RSA engine
openssl \
rsautl -decrypt -inkey $PRIVKEY -in test -out issue

# Check if the files are different
diff /etc/issue issue

# Cleanup
rm -f test issue
