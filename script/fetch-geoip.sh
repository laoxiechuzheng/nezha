#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET="$ROOT_DIR/pkg/geoip/geoip.db"
TOKEN=${IPINFO_TOKEN:-}

if [ -n "$TOKEN" ]; then
  SOURCE="IPInfo"
  URL="https://ipinfo.io/data/free/country.mmdb?token=$TOKEN"
else
  SOURCE="GeoLite2 public fallback"
  URL=${GEOIP_DB_URL:-"https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb"}
fi

TMP="$TARGET.tmp"
trap 'rm -f "$TMP"' EXIT HUP INT TERM

echo "Downloading GeoIP database from $SOURCE"
curl --fail --location --silent --show-error \
  --output "$TMP" \
  "$URL"

SIZE=$(wc -c < "$TMP" | tr -d ' ')
if [ "$SIZE" -lt 100000 ]; then
  echo "downloaded GeoIP database is unexpectedly small: $SIZE bytes" >&2
  exit 1
fi
if ! grep -a -q "MaxMind.com" "$TMP"; then
  echo "downloaded file is not a valid MaxMind database" >&2
  exit 1
fi

mv -f "$TMP" "$TARGET"
trap - EXIT HUP INT TERM
echo "GeoIP database ready from $SOURCE: $SIZE bytes"
