# A minimal test harness for the p11-kit OpenSSL engine

# Requires:
# * an actual token to work with PAP (accepts empty password)
#   GNOME Keyring works well
# * GnuTLS
#   Provides p11tool to manipulate the token

TOKEN='pkcs11:model=1.0;manufacturer=Gnome%20Keyring;serial=1%3aUSER%3aDEFAULT;token=Gnome2%20Key%20Storage'

set -e

do_check ()
{
	rm -f test issue

	# Execute
	tee /dev/stderr |$* openssl

	# Decrypt with the default RSA engine
	openssl rsautl -decrypt -inkey test.key -in test -out issue

	# Check if the files are different
	diff /etc/issue issue
}

# Pre-test fixture clean up
rm -f test.key
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Generate a test key
openssl genrsa >test.key

# Load the private key to the token
p11tool --batch --login --label=Test-Server --write --load-privkey=test.key "$TOKEN"

# Perform encryption
do_check <<EOF
engine -t -pre SO_PATH:$PWD/.libs/libp11-kit-engine.so -pre LIST_ADD:1 -pre LOAD dynamic
rsautl -engine pkcs11 -keyform engine -encrypt -inkey '$TOKEN;object=Test-Server;type=private;pin-value=' -in /etc/issue -out $PWD/test
EOF

# Perform encryption using a particular module
do_check <<EOF
engine -t -pre SO_PATH:$PWD/.libs/libp11-kit-engine.so -pre LIST_ADD:1 -pre LOAD -post MODULE_PATH:$(pkg-config --variable=p11_module_path p11-kit-1)/gnome-keyring-pkcs11.so dynamic
rsautl -engine pkcs11 -keyform engine -encrypt -inkey '$TOKEN;object=Test-Server;type=private;pin-value=' -in /etc/issue -out $PWD/test
EOF

# Perform encryption using p11-kit remoting
do_check env -i <<EOF
engine -t -pre SO_PATH:$PWD/.libs/libp11-kit-engine.so -pre LIST_ADD:1 -pre LOAD -post MODULE_PATH:unix:path=$XDG_RUNTIME_DIR/p11-kit/pkcs11 dynamic
rsautl -engine pkcs11 -keyform engine -encrypt -inkey '$TOKEN;object=Test-Server;type=private;pin-value=' -in /etc/issue -out $PWD/test
EOF

# Drop the object from the token
p11tool --batch --login --delete "$TOKEN;object=Test-Server" 2>/dev/null || :

# Cleanup
rm -f test issue test.key
