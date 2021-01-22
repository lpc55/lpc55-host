#!/bin/bash -e

label="lpc55-$(openssl rand -hex 8)"
so_pin="1234"
user_pin="1234"

echo Using label ${label}
softhsm2-util --init-token --label "${label}" --free --so-pin "${so_pin}" --pin "${user_pin}"

