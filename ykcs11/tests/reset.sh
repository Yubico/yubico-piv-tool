BIN="../../tool/yubico-piv-tool${EXEEXT}"

# Verify that user has confirmed destructive hw-tests
if [ "x$YKPIV_ENV_HWTESTS_CONFIRMED" != "x1" ]; then
    printf "\n***\n*** Hardware tests skipped.  Run \"make hwcheck\".\n***\n\n" >&0
    exit 77 # exit code 77 == skipped tests
fi

# Reset
$BIN -averify-pin -P000000 || true
$BIN -averify-pin -P000000 || true
$BIN -averify-pin -P000000 || true
$BIN -averify-pin -P000000 || true
$BIN -averify-pin -P000000 || true
$BIN -achange-puk -P000000 -N00000000 || true
$BIN -achange-puk -P000000 -N00000000 || true
$BIN -achange-puk -P000000 -N00000000 || true
$BIN -achange-puk -P000000 -N00000000 || true
$BIN -achange-puk -P000000 -N00000000 || true
$BIN -areset
