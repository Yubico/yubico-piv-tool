#!/usr/bin/env bats

# BATS test script for yubico-piv-tool

load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup_file(){
  echo "-----------------------------------------------" >&3
  echo "--- Configuration via Environment Variables ---" >&3
  echo "SLOTS_MODE:    Which slots to run tests on: 'ac' runs tests on slots 9a and 9c, 'acde' runs tests on slots 9a, 9c, 9d and 9e, 'all' runs tests on all slots" >&3
  echo "MODULE:        path to PKCS11 module." >&3
  echo "-----------------------------------------------" >&3

  local default_module_path="../../../build/ykcs11/libykcs11.dylib"
  local winpath=$(uname -o)
  
  if [ "x$winpath" = "xMsys" ]; then
    default_module_path="C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
    export MSYS2_ARG_CONV_EXCL=* # To prevent path conversion by MSYS2
  elif [[ "$winpath" == "GNU/Linux" || "$winpath" == "Darwin" ]]; then
    default_module_path="/usr/local/lib/libykcs11.dylib"
  fi

  export BIN="${pkcs11_tool:-pkcs11-tool}"
  export SLOTS_MODE="${SLOTS_MODE:-ac}"
  export MODULE="${MODULE:-$default_module_path}"

  if ! "$BIN" --module "$MODULE" --list-slots >/dev/null 2>&1; then
    echo "Module "$MODULE" not found or not executable" >&3
    exit 1
  fi
   
  if [ -e BATS_TEST_DIR ]; then
    rm -rf BATS_TEST_DIR
  fi
    mkdir BATS_TEST_DIR
    cd BATS_TEST_DIR
    echo "test signing data" > data.txt

  echo "" >&3
  echo "WARNING! This test script can overwrite any existing YubiKey content" >&3
  echo "" >&3
  echo "Press Enter to continue or Ctrl-C to abort" >&3
  read -p ""

  

  # --- Define Test Parameters ---
  slots_mode_lower=$(echo "$SLOTS_MODE" | tr '[:upper:]' '[:lower:]')
  export SLOTS=2
  if [ "x$slots_mode_lower" == "xacde" ]; then
    SLOTS=4
  elif [ "x$slots_mode_lower" == "xall" ]; then
    SLOTS=24
  fi

  if "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:edwards25519; then
    export NEWKEY_SUPPORTED=true
  fi

  RSA_KEYSIZE=("1024" "2048")
  if [ "$NEWKEY_SUPPORTED" = true ]; then
    RSA_KEYSIZE+=("3072" "4096")
  fi
  export RSA_KEYSIZE_STR="${RSA_KEYSIZE[*]}"

  EC_ALGOS=("ECCP256" "ECCP384")
  export EC_ALGOS_STR="${EC_ALGOS[*]}"

  EC_CURVES=("prime256v1" "secp384r1")
  export EC_CURVES_STR="${EC_CURVES[*]}"

  HASH_SIZES=("1" "256" "384" "512")
  export HASH_SIZES_STR="${HASH_SIZES[*]}"

  echo "-----------------------------------------------" >&3
}

@test "Variables Check" {
    local RSA_KEYSIZE=($RSA_KEYSIZE_STR)
    local EC_ALGOS=($EC_ALGOS_STR)
    local EC_CURVES=($EC_CURVES_STR)
    local HASH_SIZES=($HASH_SIZES_STR)
    
    echo "Newkey: $NEWKEY_SUPPORTED" >&3
    echo "EC curves: ${EC_CURVES[*]}" >&3
    echo "Hash sizes: ${HASH_SIZES[*]}" >&3
    echo "EC algos: ${EC_ALGOS[*]}" >&3
    echo "RSA Key Sizes to test: ${RSA_KEYSIZE[@]}" >&3
    echo "Slots: $SLOTS" >&3
    echo "Slots Mode: $SLOTS_MODE" >&3
    echo "BIN: "$BIN"" >&3
    echo "Module: "$MODULE"" >&3

    echo "-----------------------------------------------" >&3

}

@test "Elliptic Curve Key Tests (prime256v1, secp384r1)" {

    local EC_ALGOS=($EC_ALGOS_STR)
    local EC_CURVES=($EC_CURVES_STR)
    local HASH_SIZES=($HASH_SIZES_STR)
 for c in ${EC_CURVES[@]}; do
  for ((s=1;s<=$SLOTS;s++)); do
    slot=$(printf "%02x" "$s")
    echo "===== Testing key in slot "$s" with curve "$c"" >&3

    run "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id "$slot" --key-type EC:"$c"
    assert_success "Generate EC keypair in slot "$s" with curve "$c""

    run  "$BIN" --module "$MODULE" --read-object --type cert --id "$slot" -o cert.der 
    assert_success "Read certificate for slot $s"


    run openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem
    assert_success "Convert certificate to PEM format"

    run openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem
    assert_success "Extract public key from certificate"

    for h in ${HASH_SIZES[@]}; do
      run "$BIN" --module "$MODULE" --sign --pin 123456 --id "$slot" -m ECDSA-SHA"$h" --signature-format openssl -i data.txt -o data.sig
      assert_success "Sign data with ECDSA-SHA$h"
      run openssl dgst -sha"$h" -verify pubkey.pem -signature data.sig data.txt 
      assert_success "Verify signature"   
    done

    run openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:"$c" -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
    assert_success "Generate EC key and self-signed certificate with OpenSSL"

    run "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object key.pem --id "$slot" --type privkey 
    assert_success "Import private key"

    run "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object cert.pem --id "$slot" --type cert
    assert_success "Import certificate"

    run "$BIN" --module "$MODULE" --read-object --type pubkey --id "$slot" -o pubkey.der
    assert_success "Read certificate key for slot "$s""
    run openssl pkey -pubin -inform der -in pubkey.der -out pubkey.pem
    assert_success "Read out public key"
    run openssl x509 -in cert.pem -pubkey -noout -out pubkey_from_cert.pem
    assert_success "Extract public key from certificate"
    run cmp pubkey.pem pubkey_from_cert.pem
    assert_success "Compare public key read from card with public key extracted from certificate"
    

    # Test signing
    for h in ${HASH_SIZES[@]}; do
      run "$BIN" --module "$MODULE" --sign --pin 123456 --id "$slot" -m ECDSA-SHA"$h" --signature-format openssl -i data.txt -o data.sig
      assert_success "Sign data with ECDSA-SHA$h"
      run openssl dgst -sha"$h" -verify pubkey.pem -signature data.sig data.txt 
      assert_success "Verify signature"
    done

  done
 done
}

@test "ED25519 Key Tests" {

  [ "$NEWKEY_SUPPORTED" = true ] || skip "ED25519 not supported on this YubiKey"
    for ((s=1;s<=$SLOTS;s++)); do
        slot=$(printf "%02x" "$s")
        echo "===== Testing ED25519 key in slot "$s"" >&3
    
        run "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id "$slot" --key-type EC:edwards25519
        assert_success "Generate ED25519 keypair in slot "$s""
    
        run "$BIN" --module "$MODULE" --read-object --type cert --id "$slot" -o cert.der 
        assert_success "Read certificate for slot "$s""

        run openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem
        assert_success "Convert certificate to PEM format"

        run openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem
        assert_success "Extract public key from certificate"

        run "$BIN" --module "$MODULE" --sign --pin 123456 --id "$slot" -m EDDSA --signature-format openssl -i data.txt -o data.sig
        assert_success "Sign data with EDDSA"
        run openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig
        assert_success "Verify signature with Openssl"
    done
}

@test "RSA Key Tests" {

  local RSA_KEYSIZE=($RSA_KEYSIZE_STR)
  local HASH_SIZES=($HASH_SIZES_STR)
  
  for k in "${RSA_KEYSIZE[@]}"; do
    for ((s=1;s<=$SLOTS;s++)); do
        slot=$(printf "%02x" "$s")
        echo "--- Testing RSA${k} in slot ${s} ---" >&3

        run "$BIN" --module "$MODULE" --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id "$slot" --key-type rsa:"$k"
        assert_success "Generate keypair"

        run "$BIN" --module "$MODULE" --read-object --type cert --id "$slot" -o cert.der 
        assert_success "Read certificate for slot "$s""

        run openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem
        assert_success "Convert certificate to PEM format"

        run openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem
        assert_success "Extract public key from certificate"

        for h in "${HASH_SIZES[@]}"; do
          run "$BIN" --module "$MODULE" --sign --pin 123456 --id "$slot" -m SHA"$h"-RSA-PKCS --signature-format openssl -i data.txt -o data.sig
          assert_success "Sign data with SHA"$h"-RSA-PKCS"
          run openssl dgst -sha"$h" -verify pubkey.pem -signature data.sig data.txt 
          assert_success "Verify signature"   
        done

        for md in "${HASH_SIZES[@]}"; do
          for mgf in "${HASH_SIZES[@]}"; do
          # Skip 1024-bit RSA keys with SHA-512 and MGF1-SHA512 because the key size is too small
            if [ "x$md" == "x512" ] || [ "x$mgf" == "x512" ] ; then
                if [ "x$k" == "x1024" ] ; then
                    continue
                fi
            fi

            run openssl pkeyutl -encrypt -pubin -inkey pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha"$md" -pkeyopt rsa_mgf1_md:sha"$mgf" -in data.txt -out data.oaep
            assert_success "Encrypt data with OpenSSL using OAEP padding: SHA"$md" and MGF1-SHA$mgf"

            if [ "x$md" == "x1" ]; then
              run "$BIN" --module "$MODULE" --decrypt --pin 123456 --id "$slot" --hash-algorithm SHA-1 --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec
              assert_success "Decrypt data using YKCS11"
            else
                run "$BIN" --module "$MODULE" --decrypt --pin 123456 --id "$slot" --hash-algorithm SHA$md --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec
                assert_success "Decrypt data using YKCS11"
            fi
            run cmp data.txt data.dec
            assert_success "Compare decrypted data with original"
          done
        done
    done
  done 
}

@test "Testing RSA Tests" {
    run "$BIN" --module "$MODULE" --login --pin 123456 --test
    echo "$output" >&3
    assert_success "Final Test"
}


