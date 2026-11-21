#!/usr/bin/env bash
# Regenerates the site's favicons and social preview image (images/og-image.png)
# from tools/icon-source.png (the FORTA icon, padded square) and the title/url in _config.yml.
# Usage: tools/make-images.sh      (needs Google Chrome + macOS sips)
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
RUBY="/opt/homebrew/opt/ruby/bin/ruby"; [ -x "$RUBY" ] || RUBY=ruby
read_cfg() { "$RUBY" -ryaml -e "c=YAML.safe_load(File.read('_config.yml'),aliases:true); print c['$1'].to_s"; }
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
TITLE="$(read_cfg title | esc)"; URL="$(printf '%s%s' "$(read_cfg url)" "$(read_cfg baseurl)" | sed -E 's#^https?://##' | esc)"
ICON="$PWD/tools/icon-source.png"

shot() { # $1=html file  $2=out png  $3=w  $4=h
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --user-data-dir="$TMP/prof" --default-background-color=00000000 \
    --window-size="$3,$4" --screenshot="$2" "file://$1" >/dev/null 2>&1
}

for s in 32 192 512; do
  sips -s format png -z "$s" "$s" "$ICON" --out "$TMP/i$s.png" >/dev/null
done
cp "$TMP/i32.png"  images/favicon-32x32.png
cp "$TMP/i192.png" images/favicon-192x192.png
cp "$TMP/i512.png" images/favicon-512x512.png
# iOS fills transparent corners with black, so give the touch icon the brand near-black behind it.
printf '<html><body style="margin:0;background:#0B0D10"><img src="file://%s" width="180" height="180" style="display:block"></body></html>' "$ICON" > "$TMP/t.html"
shot "$TMP/t.html" images/apple-touch-icon-180x180.png 180 180
sips -s format ico "$TMP/i32.png" --out images/favicon.ico >/dev/null

cat > "$TMP/og.html" <<HTML
<html><body style="margin:0;width:1200px;height:630px;background:#0d1117;color:#e6edf3;
font-family:-apple-system,'Helvetica Neue',Arial,sans-serif;display:flex;align-items:center">
<div style="padding:0 90px;display:flex;align-items:center;gap:70px">
  <img src="file://${ICON}" width="220" height="220" alt="">
  <div>
    <div style="font-size:76px;font-weight:700;line-height:1.1">${TITLE}</div>
    <div style="font-size:36px;color:#8b949e;margin-top:22px">certifications &middot; hackthebox &middot; projects</div>
    <div style="font-size:30px;color:#3ddc84;margin-top:40px;font-family:Menlo,monospace">${URL}</div>
  </div>
</div></body></html>
HTML
shot "$TMP/og.html" images/og-image.png 1200 630
# No metadata in anything we publish.
exiftool -q -m -overwrite_original -all= images/favicon-*.png images/apple-touch-icon-180x180.png images/og-image.png 2>/dev/null || true
echo "Regenerated favicons + og-image for: ${TITLE} (${URL})"
