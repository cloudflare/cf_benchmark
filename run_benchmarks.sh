#!/bin/bash

if [ -z "$1" ]; then
	out=`pwd`/results.csv
else
	out=`pwd`/$1
fi

echo $out

nprocs=`cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l`

if [ -x /usr/bin/apt-get ] || [ -x /usr/bin/apt ]; then
       sudo apt-get install -y build-essential bc golang-1.15
elif [ -x /usr/bin/rpm ] || [ -x /usr/bin/dnf ]; then
       sudo dnf install -y golang-1.15
elif [ -x /usr/bin/pacman ]; then
       sudo pacman --noconfirm -S go
fi

export GOPATH="$(dirname "$(readlink -f "$0")")"

git submodule update --init --recursive
go get -u -v golang.org/x/crypto/chacha20poly1305/...

# Build openssl
cd openssl
if [ ! -f ./apps/openssl ]; then
	./config no-shared && make -j
fi
cd ..

# Build compression
cd comp_bench
if [ ! -f ./bench ]; then
	make
fi
cd ..

# Build lua bench
cd bench_lua
if [ ! -f ./bench ]; then
	make
fi
cd ..


openssl_aead () {
	res=`./openssl/apps/openssl speed -seconds 10 -bytes 16384 -multi $2 -evp $1 | tail -1  | rev | cut -f 1 -d ' ' | rev | sed 's/k//' `
	gib=`echo "scale=3; $res * 1000 / 1024 / 1024 / 1024" | bc`
	echo $gib GiB/s
}

openssl_sign () {
	res=`./openssl/apps/openssl speed -seconds 10 -multi $2 $1 | tail -1  | tr -s ' ' | rev | cut -f 2 -d ' ' | rev`
	echo $res ops/s
}

openssl_verify () {
	res=`./openssl/apps/openssl speed -seconds 10 -multi $2 $1 | tail -1  | tr -s ' ' | rev | cut -f 1 -d ' ' | rev` 
	echo $res ops/s
}

comp () {
	res=`./comp_bench/bench -q $1 -c $2 $3 ./comp_bench/index.html | tail -1 | cut -f 2 -d','`
	echo $res MiB/s
}

lua () {
	res=`./bench_lua/bench -c $2 ./bench_lua/$1 | tail -1 | cut -f 2 -d' '`
	echo $res ops/s
}

echo benchmark,1 core,$nprocs cores | tee $out

echo openssl pki performance | tee -a $out
for sig in ecdsap256 rsa2048 rsa3072; do
	echo $sig Sign,$( openssl_sign $sig 1), $( openssl_sign $sig $nprocs) | tee -a $out
	echo $sig Verify,$( openssl_verify $sig 1), $( openssl_verify $sig $nprocs) | tee -a $out
done

for kx in ecdhp256 ecdhx25519; do
	echo $kx Key-Exchange,$( openssl_verify $kx 1), $( openssl_verify $kx $nprocs) | tee -a $out
done

echo openssl aead performance | tee -a $out
for aead in aes-128-gcm aes-256-gcm chacha20-poly1305; do
	echo $aead,$( openssl_aead $aead 1 ), $( openssl_aead $aead $nprocs ) | tee -a $out
done

echo "LuaJIT performance" | tee -a $out
for f in binary_trees.lua fasta.lua  fibonacci.lua mandelbrot.lua  n_body.lua  spectral.lua; do
	echo lua $f,$( lua $f 1 ),$( lua $f $nprocs ) | tee -a $out
done

echo "brotli performance" | tee -a $out
for q in {4..11}; do
	echo brotli -$q,$( comp $q 1 -b),$( comp $q $nprocs -b ) | tee -a $out
done

echo "gzip performance (cloudflare zlib)" | tee -a $out
for q in {4..9}; do
	echo gzip -$q,$( comp $q 1 ),$( comp $q $nprocs ) | tee -a $out
done

echo "Go performance" | tee -a $out
go run ./go_benchmarks.go | tee -a $out
