rule Trojan_MacOS_AtomicSteal_A_2147846262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AtomicSteal.A"
        threat_id = "2147846262"
        type = "Trojan"
        platform = "MacOS: "
        family = "AtomicSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_2 = "Ronin WalletSERIALNUMBERSecPolicyOidSora_SompengSyloti_NagriTrust Wallet" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-16] 69 57 61 6c 6c 65 74 69 6e 76 61 6c 69 64 6c 6f 6f 6b 75 70 20 6d 69 6e 70 63 3d 20 6e 69 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "/Users/iluhaboltov/Desktop/amos" ascii //weight: 1
        $x_1_5 = "http://amos-malware.ru/sendlog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_AtomicSteal_B_2147846263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AtomicSteal.B"
        threat_id = "2147846263"
        type = "Trojan"
        platform = "MacOS: "
        family = "AtomicSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openssl enc -base64 -d -aes-128-cbc -iv '20202020202020202020202020202020'" ascii //weight: 1
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_3 = "ATOMIC STEALER COOCKIE.PRO" ascii //weight: 1
        $x_1_4 = "Wallets/Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AtomicSteal_C_2147891593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AtomicSteal.C"
        threat_id = "2147891593"
        type = "Trojan"
        platform = "MacOS: "
        family = "AtomicSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 63 6f 6e 66 69 67 2e 76 64 66 00 53 74 65 61 6d 2f 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 53 74 65 61 6d 2f 63 6f 6e 66 69 67 2e 76 64 66}  //weight: 2, accuracy: High
        $x_2_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 2
        $x_1_3 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 00 75 73 65 72 00 55 53 45 52 00 75 73 65 72 6e 61 6d 65 00 2f 66 67 2f 00 46 69 6c 65 47 72 61 62 62 65 72 2f}  //weight: 1, accuracy: High
        $x_1_4 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 53 6f 66 74 77 61 72 65 44 61 74 61 54 79 70 65 20 53 50 53 6f 66 74 77 61 72 65 44 61 74 61 54 79 70 65 00 25 73 00 75 73 65 72 00 55 53 45 52 00 75 73 65 72 6e 61 6d 65 00 2f 66 67 2f 00 46 69 6c 65 47 72 61 62 62 65 72 2f}  //weight: 1, accuracy: High
        $x_2_5 = {61 74 6f 6d 69 63 2f 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 2f 6c 65 76 65 6c 64 62 2f 00 64 65 73 6b 77 61 6c 6c 65 74 73 2f 45 6c 65 63 74 72 75 6d 2f 00 64 65 73 6b 77 61 6c 6c 65 74 73 2f 43 6f 69 6e 6f 6d 69 2f 00 64 65 73 6b 77 61 6c 6c 65 74 73 2f 45 78 6f 64 75 73 2f 00 64 65 73 6b 77 61 6c 6c 65 74 73 2f 41 74 6f 6d 69 63 2f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_AtomicSteal_D_2147900430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AtomicSteal.D"
        threat_id = "2147900430"
        type = "Trojan"
        platform = "MacOS: "
        family = "AtomicSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 68 72 6f 6d 69 75 6d 2f 00 2f 43 6f 6f 6b 69 65 73 00 4c 6f 67 69 6e 20 44 61 74 61 00 2f 50 61 73 73 77 6f 72 64 00 57 65 62 20 44 61 74 61 00 2f 41 75 74 6f 66 69 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {2f 57 61 6c 6c 65 74 73 2f 00 5f 00 45 78 6f 64 75 73 00 45 6c 65 63 74 72 75 6d 00 43 6f 69 6e 6f 6d 69 00 47 75 61 72 64 61 00 57 61 73 61 62 69}  //weight: 1, accuracy: High
        $x_1_3 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 44 69 73 70 6c 61 79 73 44 61 74 61 54 79 70 65 00 73 77 5f 76 65 72 73}  //weight: 1, accuracy: High
        $x_1_4 = "dscl /Local/Default -authonly" ascii //weight: 1
        $x_1_5 = "/Library/Keychains/login.keychain-db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

