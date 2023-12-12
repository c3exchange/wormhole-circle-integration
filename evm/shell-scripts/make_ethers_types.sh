#!/usr/bin/env bash

SRC=$(dirname $0)/../out
DST=$(dirname $0)/../ts/src/ethers-contracts

typechain --target=ethers-v5 --node16-modules --out-dir=$DST $SRC/*/*.json
