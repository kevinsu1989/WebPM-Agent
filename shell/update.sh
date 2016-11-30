#!/bin/sh
# 调用方式 build.sh 远程git仓库地址 本地仓库目录 构建目录

#更新包地址
UPDATESOURCE=$1
#更新目录
UPDATEPATH=$2

cd "$UPDATEPATH"

wget "$UPDATESOURCE"
