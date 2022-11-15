# Suricata

[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/suricata.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:suricata)
[![codecov](https://codecov.io/gh/OISF/suricata/branch/master/graph/badge.svg?token=QRyyn2BSo1)](https://codecov.io/gh/OISF/suricata)

# Introduction

[Suricata](https://suricata.io) là một công cụ mạng IDS, IPS và NSM engine được phát triển bởi [OISF](https://oisf.net) và Suricata community.

Fork này thêm tính năng cho bản tin Diameter

# Installation

## Các gói dependence

```
sudo apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                libcap-ng-dev libcap-ng0 make libmagic-dev         \
                libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev \
                python-yaml rustc cargo
sudo apt install libpcre2-dev libjansson-dev
```
`cbindgen v0.24.3`
```
cargo install --force cbindgen
```
Thêm path của `cbindgen` vào
```
vim ~/.bashrc
```
Thêm:
```
export PATH="$HOME/.cargo/bin:$PATH"
```

## Cài suricata
```
git clone https://github.com/maduc238/suricata.git
```
```
cd suricata
git clone https://github.com/OISF/libhtp
```
Chạy `./autogen.sh`
```
./autogen.sh
```
Install
```
./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
```
## Test file `.pcap`
```
suricata -c suricata.yaml -r file.pcap -v -k none
```
# User Guide

Bạn có thể đọc tài liệu hướng dẫn tại đây: [Suricata user guide](https://suricata.readthedocs.io/en/latest/)

# Contributing

We're happily taking patches and other contributions. Please see https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Contributing for how to get started.

Suricata is a complex piece of software dealing with mostly untrusted input. Mishandling this input will have serious consequences:

Suricata là một phần mềm phức tạp, nó sẽ xử lý hầu hết các dữ liệu mạng vào không tin cậy. Xử lý sai dữ liệu sẽ gây ra hậu quả:
- Trong IPS mode có thể khiến mạng của bạn offline;
- Ở passive moode, sử dụng IDS có thể gây mất dữ liệu quan trọng và bí mật;
- Không lọc mạng kỹ sẽ kiến mạng bị xâm phạm mà ta không biết trước
