#!/usr/bin/env bash
set -euo pipefail

cd src/

rm ../dist/*.zip || echo "No ZIPs to delete"
rm -rf .target || echo "No .target/ to delete"
mkdir .target

python3 -m pip install --upgrade pip
python3 -m pip install \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --only-binary=:all: \
  --upgrade \
  --python-version "3.13" \
  --target .target/ \
  --no-user \
  -r requirements.txt

cp ./*.py .target/

cd .target/ || exit 1

find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

zip -r ../../dist/lambda.zip .

cd ../../
