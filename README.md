# Suricata

[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/suricata.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:suricata)
[![codecov](https://codecov.io/gh/OISF/suricata/branch/master/graph/badge.svg?token=QRyyn2BSo1)](https://codecov.io/gh/OISF/suricata)

# Introduction

[Suricata](https://suricata.io) is a network IDS, IPS and NSM engine developed by the [OISF](https://oisf.net) and the Suricata community.

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

# User Guide

You can follow the [Suricata user guide](https://suricata.readthedocs.io/en/latest/) to get started.

# Contributing

We're happily taking patches and other contributions. Please see https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Contributing for how to get started.

Suricata is a complex piece of software dealing with mostly untrusted input. Mishandling this input will have serious consequences:

* in IPS mode a crash may knock a network offline;
* in passive mode a compromise of the IDS may lead to loss of critical and confidential data;
* missed detection may lead to undetected compromise of the network.

In other words, we think the stakes are pretty high, especially since in many common cases the IDS/IPS will be directly reachable by an attacker.

For this reason, we have developed a QA process that is quite extensive. A consequence is that contributing to Suricata can be a somewhat lengthy process.

On a high level, the steps are:

1. Github-CI based checks. This runs automatically when a pull request is made.

2. Review by devs from the team and community

3. QA runs from private QA setups. These are private due to the nature of the test traffic.
