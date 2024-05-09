#!/bin/bash

tc qdisc add dev $1 clsact
tc filter add dev $1 ingress bpf da obj ringbuf-output.bpf.o sec ingress
