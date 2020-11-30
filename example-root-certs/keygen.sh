#!/bin/zsh

bits=2048

if [ -z "$1" ]
  then
    echo "Usage: $0 <index>"
    echo "where <index> is 0-3, indicating which cert in ROTKH table."
    exit 1
fi

country=US
state=Delaware
organization=SoloKeys
unit="Firmware Authority $1"
CN=solokeys.com
email=ca@solokeys.com

CA_PRIVATE="ca_private_key_$1.pem"
CA_CERT="ca_certificate_$1.pem"
CA_DER="ca_certificate_$1.der"

# rm -f "$CA_PRIVATE".csr "$CA_PRIVATE" "$CA_CERT" "$CA_DER"

echo Now making the root cert

# Generate root private key
openssl genrsa -out "$CA_PRIVATE" $bits

# generate a "signing request"
openssl req -new -key "$CA_PRIVATE" -out "$CA_PRIVATE".csr  -subj "/C=$country/ST=$state/O=$organization/OU=$unit/CN=$CN/emailAddress=$email"

# self sign the request
# NB: see NXP AN12283, section 3.3 on this serial number
openssl x509 -req -days 18250 -in "$CA_PRIVATE".csr -signkey "$CA_PRIVATE" -sha256 -outform der -out \
	"$CA_DER" -extfile v3.ext -set_serial 0x3cc30000abababab

# print out information and verify
echo generated 0, view with "openssl x509 -inform der -in "$CA_DER" -text -noout"

rm "$CA_PRIVATE".csr
