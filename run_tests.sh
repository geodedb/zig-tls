#!/bin/bash
# Comprehensive test runner for zig-tls
# Runs all module tests and reports coverage

set -e

PASS=0
FAIL=0
TOTAL_TESTS=0

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        TLS 1.3 for QUIC - Comprehensive Test Suite            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

# Test modules with their expected test counts
declare -A modules=(
    ["src/key_schedule.zig"]=17
    ["src/record.zig"]=28
    ["src/alert.zig"]=14
    ["src/zero_rtt.zig"]=3
)

for module in "${!modules[@]}"; do
    expected=${modules[$module]}
    echo "┌─ Testing: $module (expected: $expected tests)"
    
    if output=$(zig test "$module" 2>&1); then
        # Extract test count from output
        if [[ $output =~ All\ ([0-9]+)\ tests\ passed ]]; then
            count="${BASH_REMATCH[1]}"
            echo "│  ✅ PASS: $count/$expected tests"
            PASS=$((PASS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + count))
        else
            echo "│  ⚠️  Unexpected output format"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "│  ❌ FAIL: Compilation or runtime error"
        echo "$output" | sed 's/^/│    /'
        FAIL=$((FAIL + 1))
    fi
    echo
done

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                        TEST SUMMARY                            ║"
echo "╠════════════════════════════════════════════════════════════════╣"
printf "║ Total Modules Tested:  %-39s ║\n" "${#modules[@]}"
printf "║ Modules Passed:        %-39s ║\n" "$PASS"
printf "║ Modules Failed:        %-39s ║\n" "$FAIL"
printf "║ Total Tests:           %-39s ║\n" "$TOTAL_TESTS"
echo "╠════════════════════════════════════════════════════════════════╣"

if [ $FAIL -eq 0 ]; then
    echo "║ Status: ✅ ALL TESTS PASSED                                   ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "║ Status: ❌ SOME TESTS FAILED                                  ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    exit 1
fi
