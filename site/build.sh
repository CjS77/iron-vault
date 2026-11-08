#!/usr/bin/env bash
# Assembles the public website in _site/: the landing page, the brand assets it uses,
# and (when it has been built) the manual under _site/manual/.
#
#   site/build.sh                  # landing page only
#   mdbook build book && site/build.sh   # landing page + manual
#
# Preview locally with:  python3 -m http.server -d _site 8000
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/_site"

rm -rf "$out"
mkdir -p "$out/assets"

cp "$root/site/index.html" "$root/site/site.css" "$out/"
for f in ironvault.css ironvault-lockup-dark.svg ironvault-lockup-light.svg ironvault-mark.svg banner-forge.webp; do
  cp "$root/assets/$f" "$out/assets/"
done

# mdbook writes to book/book/html when more than one renderer is configured (html + linkcheck2).
manual="$root/book/book/html"
if [ -d "$manual" ]; then
  cp -R "$manual" "$out/manual"
else
  echo "note: $manual not found; run 'mdbook build book' first to include the manual" >&2
fi

echo "site assembled in $out"
