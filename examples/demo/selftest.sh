#!/bin/sh
# Stand-in for a test suite that runs inside the container and then exits.
set -eu
dir=$(mktemp -d)
printf 'hello\n' > "$dir/greeting"
grep -q hello "$dir/greeting"
ls -l "$dir" > /dev/null
id > /dev/null
sleep 2
rm -r "$dir"
echo "selftest passed"
