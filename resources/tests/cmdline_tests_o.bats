#!/usr/bin/env bats

# BATS test script for yubico-piv-tool

load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'
#load 'test_helper/bats-file/load'

setup_file() {

  
  echo "--- Configuration via Environment Variables ---" >&3
  echo "YUBICO_PIV_TOOL: Path to the yubico-piv-tool executable." >&3
  echo "SLOTS_MODE:      Which slots to test ('ac', 'acde', or 'all'). Defaults to 'ac'" >&3
  echo "ENC_MODE:        Set to 'enc' to run tests over an encrypted channel." >&3
  echo "-----------------------------------------------" >&3

  local default_bin_path="yubico-piv-tool"
  local winpath
  winpath=$(uname -o) 

  if [[ "$winpath" == "Msys" ]]; then
    default_bin_path="/c/Program Files/Yubico/Yubico PIV Tool/bin/yubico-piv-tool.exe"
    export MSYS2_ARG_CONV_EXCL=* # To prevent path conversion by MSYS2

  elif [[ "$winpath" == "GNU/Linux" || "$winpath" == "Darwin" ]]; then
    default_bin_path="/usr/local/bin/yubico-piv-tool"
  fi

  export BIN="${YUBICO_PIV_TOOL:-$default_bin_path}"
  export SLOTS_MODE="${SLOTS_MODE:-ac}"
  export NEWKEY_SUPPORTED=false

  if [ -e BATS_TEST_DIR ]; then
    rm -rf BATS_TEST_DIR
  fi
  mkdir BATS_TEST_DIR
  cd BATS_TEST_DIR
  echo "test signing data" > data.txt

  # --- YubiKey Reset ---
  #echo "**********************************"
  #echo "        Resetting YubiKey..."
  #echo "**********************************"
  echo "This will reset your YubiKey, press ctrl + c to exit or y + enter to continue" >&3

  if ! "$BIN" -areset --global >/dev/null 2>&1; then
    echo "Attempting manual reset" >&3

    "$BIN" -averify-pin -P000000 || true
    "$BIN" -averify-pin -P000000 || true
    "$BIN" -averify-pin -P000000 || true
    "$BIN" -averify-pin -P000000 || true
    "$BIN" -averify-pin -P000000 || true
    "$BIN" -achange-puk -P000000 -N00000000 || true
    "$BIN" -achange-puk -P000000 -N00000000 || true
    "$BIN" -achange-puk -P000000 -N00000000 || true
    "$BIN" -achange-puk -P000000 -N00000000 || true
    "$BIN" -achange-puk -P000000 -N00000000 || true

    "$BIN" -areset || true
fi

set -e

  # Enable encrypted channel if requested, currently disabled
  args=()
  enc_mode_lower=$(echo "$ENC_MODE" | tr '[:upper:]' '[:lower:]')
  if [ "x$enc_mode_lower" == "xenc" ]; then
    args+=("--enc")
    export args_string="${args[*]}" 
    echo "Running tests over encrypted channel" >&3
  fi

  # --- Define Test Parameters ---
  slots_mode_lower=$(echo "$SLOTS_MODE" | tr '[:upper:]' '[:lower:]')
  export SLOTS_STR="9a 9c"
  if [ "x$slots_mode_lower" == "xacde" ]; then
    SLOTS_STR="9a 9c 9d 9e"
  elif [ "x$slots_mode_lower" == "xall" ]; then
    SLOTS_STR="9a 9c 9d 9e 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95"
  fi


  # Try to generate ED25519 key to see if the YubiKey support 'new' algorithms
  if "$BIN" -a generate -s 9a -A ED25519 > /dev/null 2>&1; then
    NEWKEY_SUPPORTED=true
  fi

  # Define key types based on support
  export RSA_KEYSIZE_STR="1024 2048"
  if [ "$NEWKEY_SUPPORTED" = true ]; then
    RSA_KEYSIZE_STR+=" 3072 4096"
  fi

  export EC_ALGOS_STR="ECCP256 ECCP384"

  export EC_CURVES_STR="prime256v1 secp384r1"

  export HASH_SIZES_STR="1 256 384 512"

  if [ "$enc_mode_lower" == "enc" ] && "$BIN" -a version; then
    run "$BIN" --enc -a version
    if [ "$status" -ne 0 ]; then
      echo "Error: The encrypted channel check failed." >&3
      echo "This might mean the --enc feature is not supported by the Yubikey." >&3
      return 1
    fi
  fi

  echo "-----------------------------------------------" >&3
}


####################
#      TESTS       #
####################

@test "Variables Check" {
    local RSA_KEYSIZE=($RSA_KEYSIZE_STR)
    local EC_ALGOS=($EC_ALGOS_STR)
    local EC_CURVES=($EC_CURVES_STR)
    local HASH_SIZES=($HASH_SIZES_STR)
    local SLOTS=($SLOTS_STR)
    local encryption=($args_string)
    
    echo "Newkey: $NEWKEY_SUPPORTED" >&3
    echo "EC curves: ${EC_CURVES[*]}" >&3
    echo "Hash sizes: ${HASH_SIZES[*]}" >&3
    echo "EC algos: ${EC_ALGOS[*]}" >&3
    echo "RSA Key Sizes to test: ${RSA_KEYSIZE[@]}" >&3
    echo "Slots: ${SLOTS[@]} " >&3
    echo "BIN: "$BIN"" >&3
    echo "Encryption: ${encryption[*]}" >&3

}

@test "Elliptic Curve Key Tests (ECCP256, ECCP384)" {
    
    local EC_ALGOS=($EC_ALGOS_STR)
    local EC_CURVES=($EC_CURVES_STR)
    local HASH_SIZES=($HASH_SIZES_STR)
    local SLOTS=($SLOTS_STR)
    local encryption=($args_string)
  for i in "${!EC_ALGOS[@]}"; do
    local k=${EC_ALGOS[i]}
    local c=${EC_CURVES[i]}
    
    for slot in "${SLOTS[@]}"; do
      echo "--- Testing $k ($c) in slot $slot ---" >&3
      # --- Generate Key ---
      run "$BIN" "${encryption[@]}" -a generate -s"$slot" -A"$k" -o pubkey.pem
      assert_success "Generate $k key in slot $slot"
      
      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -S"/CN=YubicoTest/OU=YubicoGeneratedECKey/O=yubico.com/" -aselfsign -i pubkey.pem -o cert.pem
      assert_success "Self-sign certificate"

      run "$BIN" "${encryption[@]}" -a import-certificate -P123456 -s"$slot" -i cert.pem
      assert_success "Import certificate"
      
      run "$BIN" "${encryption[@]}" -a read-public-key -s"$slot" -o pubkey_gen.pub
      assert_success "Read back public key"

      run cmp pubkey.pem pubkey_gen.pub
      assert_success "Compare generated and retrieved public key"

      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-signature -i cert.pem
      assert_success "Test signature"

      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-decipher -i cert.pem
      assert_success "Test decryption"

      run "$BIN" "${encryption[@]}" -a attest -s"$slot"
      assert_success "Attest private key"

      STATUS=$("$BIN" "${encryption[@]}" -a status)
      echo "$STATUS"
      ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
      if [ "x$ALGO" != "xPublicKeyAlgorithm:$k" ]; then
        echo "$ALGO" >&3
        exit 1
      fi

      SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
      if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTest,OU=YubicoGeneratedECKey,O=yubico.com" ]; then
        echo "$SUBJECT" >&3
        exit 1
      fi

      # --- Signing with generated key ---
      for h in "${HASH_SIZES[@]}"; do
      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 --sign -s "$slot" -A "$k" -H "SHA$h" -i data.txt -o data.sig
      assert_success "Sign with SHA${h}-$k"

      run openssl dgst -sha"$h" -verify pubkey.pem -signature data.sig data.txt
      assert_success "Verify signature with OpenSSL"
      done
      # --- Import key into slot ---
      run openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:$c -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
      assert_success "Generate external key with OpenSSL"

      run "$BIN" "${encryption[@]}" -a import-key -s"$slot" -i key.pem
      assert_success "Import private key"

      run "$BIN" "${encryption[@]}" -a import-certificate -s"$slot" -i cert.pem
      assert_success "Import certificate for external key"

      run "$BIN" "${encryption[@]}" -a read-public-key -s"$slot" -o pubkey.pem
      assert_success "Get public key of imported key"

      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-signature -i cert.pem
      assert_success "Test signature of imported key"

      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-decipher -i cert.pem
      assert_success "Test decryption of imported key"

      # --- Read status and validate fields for imported key ---
      STATUS=$("$BIN" "${encryption[@]}" -astatus)
      echo "$STATUS"
      ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
      if [ "x$ALGO" != "xPublicKeyAlgorithm:$k" ]; then
        echo "$ALGO" >&3
        exit 1
      fi

      SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
      if [ "x$SUBJECT" != "xSubjectDN:CN=OpenSSLGeneratedECKey" ]; then
        echo "$SUBJECT" >&3
        exit 1
      fi
      # --- Signing with imported key ---
      for h in "${HASH_SIZES[@]}"; do
      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 --sign -s $slot -A $k -H SHA$h -i data.txt -o data.sig 
      assert_success "Sign with SHA${h}-$k using imported key"

      run openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt
      assert_success "Verify signature with OpenSSL"
      done 
      # --- Clean up ---
      if [ "$NEWKEY_SUPPORTED" = "true" ]; then
        run "$BIN" "${encryption[@]}" -a delete-key -s"$slot"
        assert_success "Delete key from slot $slot"
      fi
    done
  done
}

@test "ED25519 Key Tests" {
  [ "$NEWKEY_SUPPORTED" = true ] || skip "ED25519 not supported on this YubiKey $NEWKEY_SUPPORTED"
  local SLOTS=($SLOTS_STR)
  local encryption=($args_string)


  

  for slot in "${SLOTS[@]}"; do
    echo "--- Testing ED25519 in slot $slot ---" >&3
    # --- Generate Key ---
    run "$BIN" "${encryption[@]}" -a generate -s"$slot" -A ED25519 -o pubkey.pem
    assert_success "Generate ED25519 key"

    run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -S'/CN=YubicoTest/OU=YubicoGeneratedEDKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
    assert_success "Self-sign ED25519 certificate"

    run "$BIN" "${encryption[@]}" -a import-certificate -P123456 -s"$slot" -i cert.pem
    assert_success "Import ED25519 certificate"
    
    run "$BIN" "${encryption[@]}" -a read-public-key -s"$slot" -o pubkey_gen.pub
    assert_success "Read back ED25519 public key"

    run cmp pubkey.pem pubkey_gen.pub
    assert_success "Compare generated and retrieved ED25519 public key"

    run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-signature -i cert.pem
    assert_success "Test ED25519 signature"

    run "$BIN" "${encryption[@]}" -a attest -s"$slot" -i $slot.pem
    assert_success "Attest ED25519 private key"

    # --- Read status and validate fields ---
    STATUS=$("$BIN" "${encryption[@]}" -astatus)
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:ED25519" ]; then
      echo "$ALGO" >&3
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTest,OU=YubicoGeneratedEDKey,O=yubico.com" ]; then
      echo "$SUBJECT" >&3
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi
    # --- Signing with generated key ---
    run "$BIN" "${encryption[@]}" -a verify-pin -P123456 --sign -s"$slot" -A ED25519 -i data.txt -o data.sig
    assert_success "Sign with ED25519"

    run openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig
    assert_success "Verify signature with OpenSSL"

    rm *.sig
    # --- Import key into slot ---
    run openssl genpkey -algorithm ED25519 -out key.pem
    assert_success "Generate ED25519 key with OpenSSL"

    run openssl req -new -out csr.pem -key key.pem  -subj "/CN=OpenSSLGeneratedEDKey/"
    assert_success "Create CSR for OpenSSL ED25519 key"

    run openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem 
    assert_success "Sign certificate with OpenSSL"

    run "$BIN" "${encryption[@]}" -a import-key -s"$slot" -i key.pem
    assert_success "Import ED25519 private key"

    run "$BIN" "${encryption[@]}" -a import-certificate -s"$slot" -i cert.pem
    assert_success "Import ED25519 certificate"

    run "$BIN" "${encryption[@]}" -a read-public-key -s"$slot" -o pubkey.pem
    assert_success "Get public key"

    run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s"$slot" -a test-signature -i cert.pem
    assert_success "Test signature"

    # --- Read status and validate fields ---
    STATUS=$("$BIN" "${encryption[@]}" -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:ED25519" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=OpenSSLGeneratedEDKey" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    # --- Signing with imported key ---
    run "$BIN" "${encryption[@]}" -averify-pin -P123456 --sign -s"$slot" -A ED25519 -i data.txt -o data.sig
    assert_success "Sign with ED25519 key"

    run openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig
    assert_success "Verify signature with OpenSSL"

    # --- Clean up ---
    if [ "$NEWKEY_SUPPORTED" = "true" ]; then
     run "$BIN" "${encryption[@]}" -a delete-key -s"$slot"
     assert_success "Delete private key"
    fi
    
  done
}

@test "RSA Key Tests" {

  # Rebuild arrays from the exported string variables from setup_file
  local RSA_KEYSIZE=($RSA_KEYSIZE_STR)
  local HASH_SIZES=($HASH_SIZES_STR)
  local SLOTS=($SLOTS_STR)
  local encryption=($args_string)


  for k in "${RSA_KEYSIZE[@]}"; do
    for slot in "${SLOTS[@]}"; do
      echo "--- Testing RSA${k} in slot ${slot} ---" >&3

      # === Generate key in slot ===
      run "$BIN" "${encryption[@]}" -a generate -s "$slot" -A "RSA$k" -o pubkey.pem
      assert_success "Generate RSA${k} key in slot ${slot}"
      
      run "$BIN" "${encryption[@]}" -a verify-pin -P123456 -s "$slot" -S '/CN=YubicoTest/OU=YubicoGeneratedRSAKey/O=yubico.com/' -a selfsign -i pubkey.pem -o cert.pem
      assert_success "Self-sign certificate for RSA${k}"
      
      run "$BIN" "${encryption[@]}" -a import-certificate -s "$slot" -i cert.pem
      assert_success "Import certificate for RSA${k}"
      run "$BIN" "${encryption[@]}" -a read-public-key -s "$slot" -o pubkey_gen.pem
      assert_success "Get public key"
      
      run cmp pubkey.pem pubkey_gen.pem
      assert_success "Compare generated and retrieved public key"
        
        
      run "$BIN" "${encryption[@]}" -a verify-pin -P 123456 -s "$slot" -a test-signature -i cert.pem
      assert_success "Test signature"

      run "$BIN" "${encryption[@]}" -a verify-pin -P 123456 -s "$slot" -a test-decipher -i cert.pem
      assert_success "Test decryption"
      
      run "$BIN" "${encryption[@]}" -a attest -s "$slot" -i "$slot.pem"
      assert_success "Attest private key"

      # --- Read status and validate fields ---
      run "$BIN" "${encryption[@]}" -a status
      assert_success "Read device status"

      local ALGO
      ALGO=$(echo "$output" | grep "Slot $slot" -A 6 | grep "Public Key Algorithm" | tr -d "[:blank:]")
      assert_equal "$ALGO" "PublicKeyAlgorithm:RSA$k"

      local SUBJECT
      SUBJECT=$(echo "$output" | grep "Slot $slot" -A 6 | grep "Subject DN" | tr -d "[:blank:]")
      assert_equal "$SUBJECT" "SubjectDN:CN=YubicoTest,OU=YubicoGeneratedRSAKey,O=yubico.com"
      # === Signing with generated key ===
      for h in "${HASH_SIZES[@]}"; do
        run "$BIN" "${encryption[@]}" -a verify-pin -P123456 --sign -s $slot -A RSA$k -H SHA$h -i data.txt -o data.sig
        assert_success "Sign with SHA${h}-RSA${k}"
        run openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt
        assert_success "Verify signature with OpenSSL"
      done
      # === Import key into slot ===
      run openssl req -newkey rsa:"$k" -keyout key.pem -nodes -x509 -days 365 -subj "/CN=OpenSSLGeneratedRSAKey/" -out cert.pem
      assert_success "Generate external RSA${k} key with OpenSSL"

      run "$BIN" "${encryption[@]}" -a import-key -s "$slot" -i key.pem
      assert_success "Import private key for RSA${k}"
      
      run "$BIN" "${encryption[@]}" -a import-certificate -s "$slot" -i cert.pem
      assert_success "Import certificate for external key"

      run "$BIN" "${encryption[@]}" -a read-public-key -s "$slot" -o pubkey.pem
      assert_success "Get public key of imported key"

      run "$BIN" "${encryption[@]}" -a verify-pin -P 123456 -s "$slot" -a test-signature -i cert.pem
      assert_success "Test signature of imported key"

      run "$BIN" "${encryption[@]}" -a verify-pin -P 123456 -s "$slot" -a test-decipher -i cert.pem
      assert_success "Test decryption of imported key"
      # --- Read status and validate fields for imported key ---
      run "$BIN" "${encryption[@]}" -a status
      assert_success "Read device status after import"

      ALGO=$(echo "$output" | grep "Slot $slot" -A 6 | grep "Public Key Algorithm" | tr -d "[:blank:]")
      assert_equal "$ALGO" "PublicKeyAlgorithm:RSA$k"

      SUBJECT=$(echo "$output" | grep "Slot $slot" -A 6 | grep "Subject DN" | tr -d "[:blank:]")
      assert_equal "$SUBJECT" "SubjectDN:CN=OpenSSLGeneratedRSAKey"
      
      # === Signing with imported key ===
      for h in "${HASH_SIZES[@]}"; do
        run "$BIN" "${encryption[@]}" -a verify-pin -P123456 --sign -s "$slot" -A "RSA$k" -H "SHA$h" -i data.txt -o data.sig
        assert_success "Sign with SHA${h}-RSA${k} using imported key"
        run openssl dgst -sha"$h" -verify pubkey.pem -signature data.sig data.txt
        assert_success "Verify signature with OpenSSL"
      done

      # === Clean up ===
      if [ "$NEWKEY_SUPPORTED" = "true" ]; then
        run "$BIN" "${encryption[@]}" -a delete-key -s "$slot"
        assert_success "Delete key from slot ${slot}"
      fi
    done
  done
}

@test "Certificate Compression Test" {
  local encryption=($args_string)
  local long_subject="/C=US/ST=CA/L=PaloAlto/O=Yubico/CN=CompressionTestCert"
  long_subject+="/OU=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  long_subject+="/OU=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
  long_subject+="/OU=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
  long_subject+="/OU=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

  run openssl req -x509 -newkey rsa:2048 -keyout key.pem -out too_large_cert.pem -sha256 -days 3650 -nodes -subj "$long_subject"
  assert_success "Generate large certificate"

  run "$BIN" "${encryption[@]}" -aimport-certificate -s9a --compress -i too_large_cert.pem
  assert_success "Import compressed certificate"

  run "$BIN" "${encryption[@]}" -aread-certificate -s9a -o too_large_cert_out.pem
  assert_success "Read back compressed certificate"

  run cmp too_large_cert.pem too_large_cert_out.pem
  assert_success "Compare read certificate with the one imported"
}