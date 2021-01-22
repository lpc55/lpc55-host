#!/usr/bin/bash -xe

export OPENSSL_CONF=./openssl-smartcardhsm.conf
# export PIN=1234

generate() {
	i=$1
	label=lpc55-host-dev-ca-${i}
	key=slot_0-label_${label}
    subject="/O=github.com\/lpc55/CN=${label}"
    # subject="/"
	csr=${label}.csr
	cert=${label}.der

	openssl req \
		-engine pkcs11 -keyform engine \
		-new \
		-key ${key} \
		-sha256 -subj "${subject}" \
		-out ${csr} \

	# openssl req -text -noout -verify -in lpc55-host-dev-ca-0.csr

	openssl x509 \
		-engine pkcs11 -keyform engine \
		-req \
		-signkey ${key} \
		-sha256 -days 7300 -extfile v3.ext -set_serial 0x3cc30000abababab \
		-in ${csr} \
		-outform der -out ${cert} \

	openssl x509 -text -noout -inform der -in lpc55-host-dev-ca-0.der
}

for i in {0..0}
do
	echo "generating CA ${i}"
	generate ${i}
done

