tmpfile=$(mktemp --suffix=.7z)
curl -L https://weakpass.com/download/2012/weakpass_4.txt.7z -o "$tmpfile"
7z x "$tmpfile" -mmt=32
rm -f "$tmpfile"
