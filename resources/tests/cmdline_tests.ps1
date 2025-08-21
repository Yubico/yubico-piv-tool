$ARCH=$args[0]
if($ARCH -eq "x86")
{
    if ((Get-Command "yubico-piv-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin"
    }
}
elseif ($ARCH -eq "x64")
{
    if ((Get-Command "yubico-piv-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files/Yubico/Yubico PIV Tool/bin"
    }
}
else
{
    echo "Usage: ./cmdline_test.ps1 <x86|x64> <path_to_yubico_piv_tool> <ac|acde|all>"
    echo ""
    echo "This is a test script that uses the yubico-piv-tool command line tool to reset the connected YubiKey and then
           generates keys on 4 different slots using 4 different key algorithms and then performs a signature with each
           of these keys."
    echo ""
    echo "   x86        expects that yubico-piv-tool is installed in 'C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin'"
    echo "   x64        expects that yubico-piv-tool is installed in 'C:/Program Files/Yubico/Yubico PIV Tool/bin'"
    echo "   <path_to_yubico_piv_tool>  path to the yubico-piv-tool command line tool, if not specified, it will be searched in the PATH"
    echo "   <ac|acde|all>  specifies which slots to use for the tests"
    # enc doesn't currently work
    #echo "   <enc>        Optional! Run the tests over en encrypted channel"
    exit
}
echo "Running commands on $ARCH architecture"
if ($args.Count -gt 2)
{
    $BIN = $args[1] # path to the yubico-piv-tool command line tool
    $CMD_SLOTS = $args[2] # ac|acde|all
}
else
{
    echo "Usage: ./cmdline_test.ps1 <x86|x64> <path_to_yubico_piv_tool> <ac|acde|all>"
    exit
}

echo ""
echo "WARNING! This test script will reset the YubiKey and delete all keys and certificates on it"
echo ""

$OutputYN = Read-Host "Do you want to continue? (Y/N)"
If ("y","n" -notcontains $OutputYN) 
{
    Do {
    $OutputYN = Read-Host "Please input either a 'Y' for yes or a 'N' for no"
    } While ("y","n" -notcontains $OutputYN)
}
if ($OutputYN -eq "N") 
{
    exit
}
elseif ($OutputYN -eq "Y") 
{
    echo "Continuing with the test script"
    echo ""
}

if (Test-Path -Path .\yubico-piv-tool_test_dir)
{
    echo "Found existing test directory, clearing contents"
    Remove-Item -Path .\yubico-piv-tool_test_dir\* -Recurse -Force
    cd yubico-piv-tool_test_dir
}
else
{   echo "Creating test directory"
    mkdir yubico-piv-tool_test_dir; cd yubico-piv-tool_test_dir
}
echo "test signing data" > data.txt
function test {
    param
    (
        [string]$Command,
        [string]$Description
    )
    Invoke-Expression "$Command" *> output.txt
    $ret = $LASTEXITCODE
    if ($ret -ne 0)
    {
        Write-Host $Command
        Get-Content output.txt
        Remove-Item output.txt
        exit 1
    }
    else
    {
        Write-Host "   $Description ... OK!"
        Remove-Item output.txt
    }
}

echo "**********************************"
echo "            Reset YubiKey"
echo "**********************************"

& $BIN -areset --global > $null 2>&1
$exitcode = $LASTEXITCODE

echo "********************** Reset YubiKey ********************* "

if ($exitcode -ne 0) {
    yubico-piv-tool.exe -averify-pin -P000000
    yubico-piv-tool.exe -averify-pin -P000000
    yubico-piv-tool.exe -averify-pin -P000000
    yubico-piv-tool.exe -averify-pin -P000000
    yubico-piv-tool.exe -averify-pin -P000000
    yubico-piv-tool.exe -achange-puk -P000000 -N00000000
    yubico-piv-tool.exe -achange-puk -P000000 -N00000000
    yubico-piv-tool.exe -achange-puk -P000000 -N00000000
    yubico-piv-tool.exe -achange-puk -P000000 -N00000000
    yubico-piv-tool.exe -achange-puk -P000000 -N00000000
    yubico-piv-tool.exe -areset
}

# Doesn't work
#if ($args.Count -eq 4 -and $args[3] -eq "enc")
#{
  #$BIN = "$BIN --scp11" # Enable encrypted channel
#}
#else {
    #echo "Running without encrypted channel"
#}

$SLOTS = @('9a', '9c')
if ($CMD_SLOTS -eq "acde")
{
    $SLOTS=@('9a', '9c', '9d', '9e')
}
elseif ($CMD_SLOTS -eq "all")
{
    $SLOTS = @('9a', '9c', '9d', '9e', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95')
}

& $BIN -agenerate -s9a -A ED25519 *> $null  # Try to generate ED25519 key to see if the YubiKey support 'new' algorithms
$newkey = $LASTEXITCODE
$RSA_KEYSIZE=@("1024", "2048")
$EC_ALGOS=@("ECCP256" ,"ECCP384")
$EC_CURVES=@("prime256v1", "secp384r1")
$HASH_SIZES=@("1" ,"256", "384" ,"512")

if ($newkey -eq 0)
{
   $RSA_KEYSIZE += "3072", "4096"
}

foreach ($i in 0..($EC_ALGOS.Count - 1))
{
    $k=$EC_ALGOS[$i]
    $c=$EC_CURVES[$i]
    echo "**********************************"
    echo "            $k"
    echo "**********************************"
    foreach ($slot in $SLOTS)
    {
        echo "=== Generate key in slot $slot"
        test "$BIN -agenerate -s$slot -A$k -o pubkey.pem" ,"Generate key"
        & $BIN -averify-pin -P123456 -s"$slot" -S'/CN=YubicoTest/OU=YubicoGeneratedECKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
        test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
        test "$BIN -aread-public-key -s$slot -o pubkey_gen.pub" "Get public key"
        test "cmp pubkey.pem pubkey_gen.pub" "Compare generated and retrieved public key"
        test "$BIN -averify-pin -P123456 -s$slot -atest-signature -i cert.pem" "Test signature"
        test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"
        test "$BIN -aattest -s$slot" "Attest private key"

        # Read status and validate fields
        $STATUS = & $BIN -astatus
        echo "$STATUS"
        $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
        $algorithmLine = ($matchInfo.Line + $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
        $ALGO = $algorithmLine.Line -replace '\s'
        $expectedValue = "PublicKeyAlgorithm:$k"

        if ($ALGO -notlike "*$expectedValue*")
        {
            echo "$ALGO"
            Write-Error "Generated algorithm incorrectly"
            exit 1
        }
        else
        {
            echo "Generated algorithm correctly"
        }

        echo "=== Signing with generated key:"

        foreach ($hash in $HASH_SIZES)
        {
            test "$BIN -a verify-pin -P123456 --sign -s $slot -A $k -H SHA$hash -i data.txt -o data.sig" "Sign with ECDSA-SHA$hash"
            test "openssl dgst -sha$hash -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
        }

        echo "=== Import key into slot $slot"
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:$c -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
        test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
        test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
        test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
        test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
        test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"

        # Read status and validate fields
        $STATUS = & $BIN -astatus
        echo "$STATUS"
        $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
        $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
        $ALGO = $algorithmLine.Line -replace '\s'
        $expectedValue = "PublicKeyAlgorithm:$k"

        if ($ALGO -notlike "*$expectedValue*")
        {
            echo "$ALGO"
            Write-Error "Generated algorithm incorrectly"
            exit 1
        }
        else
        {
            echo "Generated algorithm correctly"
        }

        $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
        $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Subject DN:"
        $SUBJECT = $algorithmLine.Line -replace '\s'
        $expectedValue = "SubjectDN:CN=OpenSSLGeneratedECKey"
        if ($SUBJECT -notlike "*$expectedValue*")
        {
            echo "$SUBJECT"
            Write-Error "Certificate subject incorrect."
            exit 1
        }
        else
        {
            echo "Certificate subject correct"
        }

        echo "=== Signing with imported key:"

        foreach ($h in $HASH_SIZES)
        {
            test "$BIN -a verify-pin -P123456 --sign -s $slot -A $k -H SHA$h -i data.txt -o data.sig" "Sign with ECDSA-SHA$h"
            test "$openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
        }
        if ($newkey -eq 0)
        {
            echo " === Clean up:"
            test "$BIN -a delete-key -s $slot" "Delete private key"
        }
    }
}
if ($newkey -eq 0)
{
  echo "**********************************"
  echo "            ED25519"
  echo "**********************************"

  foreach ($slot in $SLOTS)
  {
     echo "=== Generate key in slot $slot"
     test "$BIN -agenerate -s$slot -A ED25519 -o pubkey.pem" "Generate key"
     & $BIN -averify-pin -P123456 -s"$slot" -S'/CN=YubicoTest/OU=YubicoGeneratedEDKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
     test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
     test "$BIN -aread-public-key -s$slot -o pubkey_gen.pub" "Get public key"
     test "cmp pubkey.pem pubkey_gen.pub" "Compare generated and retrieved public key"
     test "$BIN -averify-pin -P123456 -s$slot -atest-signature -i cert.pem" "Test signature"
     test "$BIN -aattest -s$slot -i $slot.pem" "Attest private key"

     # Read status and validate fields
     $STATUS=$( & $BIN -astatus)
     echo "$STATUS"
     $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
     $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
     $ALGO = $algorithmLine.Line -replace '\s'
     $expectedValue = "PublicKeyAlgorithm:ED25519"
     if ($ALGO -notlike "*$expectedValue*")
     {
        echo "$ALGO"
        Write-Error "Generated algorithm incorrectly"
        exit 1
     }
     else
     {
        echo "Generated algorithm correctly"
     }
     $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
     $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Subject DN"
     $SUBJECT = $algorithmLine.Line -replace '\s'
     $expectedValue = "SubjectDN:CN=YubicoTest,OU=YubicoGeneratedEDKey,O=yubico.com"
     if ($SUBJECT -notlike "*$expectedValue*")
     {
        echo "$SUBJECT"
        Write-Error "Certificate subject incorrect."
        exit 1
     }
     else
     {
        echo "Certificate subject correct"
     }
     echo "=== Signing with generated key:"
     test "$BIN -a verify-pin -P123456 --sign -s $slot -A ED25519 -i data.txt -o data.sig" "Sign with ED25519 key"
     test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"
     rm *.sig

     echo "=== Import key into slot $slot"

     test "openssl genpkey -algorithm ED25519 -out key.pem" "Generate ED25519 private key with OpenSSL"
     openssl req -new -out csr.pem -key key.pem  -subj "/CN=OpenSSLGeneratedEDKey/"
     test "openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem" "Sign certificate with OpenSSL"
     test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
     test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
     test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
     test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"

     # Read status and validate fields
     $STATUS=$(& $BIN -astatus)
     echo "$STATUS"
     $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
     $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
     $ALGO = $algorithmLine.Line -replace '\s'
     $expectedValue = "PublicKeyAlgorithm:ED25519"
     if ($ALGO -notlike "*$expectedValue*")
     {
        echo "$ALGO"
        Write-Error "Generated algorithm incorrectly"
        exit 1
     }
     else
     {
        echo "Generated algorithm correctly"
     }

     $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
     $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Subject DN"
     $SUBJECT = $algorithmLine.Line -replace '\s'
     $expectedValue = "SubjectDN:CN=OpenSSLGeneratedEDKey"
     if ($SUBJECT -notlike "*$expectedValue*")
     {
        echo "$SUBJECT"
        Write-Error "Certificate subject incorrect."
        exit 1
     }
     else
     {
        echo "Certificate subject correct"
     }

     echo "=== Signing with imported key:"
     test "$BIN -a verify-pin -P123456 --sign -s $slot -A ED25519 -i data.txt -o data.sig" "Sign with ED25519 key"
     test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"
     if ($newkey -eq 0)
     {
        echo "=== Clean up:"
        test "$BIN -a delete-key -s $slot" "Delete private key"
     }
  }
}
foreach ($k in $RSA_KEYSIZE)
{
 echo "**********************************"
 echo "            RSA$k"
 echo "**********************************"

 foreach ($slot in $SLOTS)
 {
    echo "=== Generate key in slot $slot"
    test "$BIN -agenerate -s$slot -ARSA$k -o pubkey.pem" "Generate key"
    & $BIN -averify-pin -P123456 -s"$slot" -S'/CN=YubicoTest/OU=YubicoGeneratedRSAKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
    test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey_gen.pem" "Get public key"
    test "cmp pubkey.pem pubkey_gen.pem" "Compare generated and retrieved public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"
    test "$BIN -a attest -s$slot -i $slot.pem" "Attest private key"

    # Read status and validate fields
    $STATUS=$(& $BIN -astatus)
    echo "$STATUS"
    $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
    $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
    $ALGO = $algorithmLine.Line -replace '\s'
    $expectedValue = "PublicKeyAlgorithm:RSA$k"
    if ($ALGO -notlike "*$expectedValue*")
    {
        echo "$ALGO"
        Write-Error "Generated algorithm incorrectly"
        exit 1
    }
    else
    {
        echo "Generated algorithm correctly"
    }

    $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
    $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Subject DN"
    $SUBJECT = $algorithmLine.Line -replace '\s'
    $expectedValue = "SubjectDN:CN=YubicoTest,OU=YubicoGeneratedRSAKey,O=yubico.com"
    if ($SUBJECT -notlike "*$expectedValue*")
    {
        echo "$SUBJECT"
        Write-Error "Certificate subject incorrect."
        exit 1
    }
    else
    {
        echo "Certificate subject correct"
    }

    echo "=== Signing with generated key:"
    foreach ($hash in $HASH_SIZES)
    {
      test "$BIN -a verify-pin -P123456 --sign -s $slot -A RSA$k -H SHA$hash -i data.txt -o data.sig" "Sign with SHA$hash-RSA-PKCS"
      test "openssl dgst -sha$hash -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    }

    echo "=== Import key into slot $slot"
    openssl req -newkey rsa:$k -keyout key.pem -nodes -x509 -days 365 -subj "/CN=OpenSSLGeneratedRSAKey/" -out cert.pem
    test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
    test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"

    # Read status and validate fields
    $STATUS=$(& $BIN -astatus)
    echo "$STATUS"
    $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
    $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Public Key Algorithm"
    $ALGO = $algorithmLine.Line -replace '\s'
    $expectedValue = "PublicKeyAlgorithm:RSA$k"
    if ($ALGO -notlike "*$expectedValue*")
    {
        echo "$ALGO"
        Write-Error "Generated algorithm incorrectly"
        exit 1
    }
    else
    {
        echo "Generated algorithm correctly"
    }

    $matchInfo = $STATUS | Select-String -Pattern "Slot $slot" -Context 0, 6
    $algorithmLine = ($matchInfo.Line, $matchInfo.Context.PostContext) | Select-String -Pattern "Subject DN"
    $SUBJECT = $algorithmLine.Line -replace '\s'
    $expectedValue = "SubjectDN:CN=OpenSSLGeneratedRSAKey"
    if ($SUBJECT -notlike "*$expectedValue*")
    {
        echo "$SUBJECT"
        Write-Error "Certificate subject incorrect."
        exit 1
    }
    else
    {
        echo "Certificate subject correct"
    }

    echo "=== Signing with imported key:"
    foreach ($h in $HASH_SIZES)
    {
        test "$BIN -a verify-pin -P123456 --sign -s $slot -A RSA$k -H SHA$h -i data.txt -o data.sig" "Sign with SHA$h-RSA-PKCS"
        test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    }
    if ($newkey -eq 0)
    {
        echo " === Clean up:"
        test "$BIN -a delete-key -s $slot" "Delete private key"
    }
 }
}
echo "****************************************************"
echo "         Compress X509 Certificate"
echo "****************************************************"

openssl req -x509 -newkey rsa:4096 -out too_large_cert.pem -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123' > $null 2>&1
test "$BIN -aimport-certificate -s9a --compress -i too_large_cert.pem" "Import compressed certificate"
test "$BIN -aread-certificate -s9a -o too_large_cert_out.pem" "Read compressed certificate"
test "cmp too_large_cert.pem too_large_cert_out.pem" "Compare read certificate with the one imported"
echo "All tests passed!"

cd ..
Remove-Item -Path "yubico-piv-tool_test_dir" -Recurse -Force