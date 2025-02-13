rule Trojan_MacOS_HashBreaker_A_2147844111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HashBreaker.A!MTB"
        threat_id = "2147844111"
        type = "Trojan"
        platform = "MacOS: "
        family = "HashBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data.Wallets" ascii //weight: 1
        $x_1_2 = "NUITKA_TICKER" ascii //weight: 1
        $x_1_3 = "data.chainbreaker" ascii //weight: 1
        $x_1_4 = "get_coinomi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_HashBreaker_A_2147844111_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HashBreaker.A!MTB"
        threat_id = "2147844111"
        type = "Trojan"
        platform = "MacOS: "
        family = "HashBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DumpKeyChain" ascii //weight: 1
        $x_1_2 = "UploadKeychain" ascii //weight: 1
        $x_1_3 = "DecryptKeychain" ascii //weight: 1
        $x_1_4 = "ExtractSafeStoragePassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_HashBreaker_B_2147844827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HashBreaker.B!MTB"
        threat_id = "2147844827"
        type = "Trojan"
        platform = "MacOS: "
        family = "HashBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 02 00 00 00 e8 a8 71 00 00 48 8d 3d b8 85 00 00 48 8d 95 40 ff ff ff 48 89 fe 31 c0 e8 06 71 00 00 48 98 48 8d 0d 39 88 fe ff 48 8d 14 08 48 8b b5 40 ff ff ff 48 89 35 77 3e 01 00 48 89 15 60 3e 01 00 48 89 15 61 3e 01 00 0f b7 14 08 66 89 95 3c ff ff ff 8a 5c 08 02 88 9d 3e ff ff ff 48 01 c8 48 83 c0 03 48 89 05 3e 3e 01 00 80 fa 4b 0f 85 39 05 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {bf 02 00 00 00 e8 3c 24 00 00 48 8d 3d 68 33 00 00 48 8d 95 40 ff ff ff 48 89 fe 31 c0 e8 ca 23 00 00 48 63 d0 48 8d 35 78 b4 fe ff 48 8d 04 32 48 89 05 0d da 00 00 48 89 05 0e da 00 00 8a 1c 32 8a 4c 32 01 8a 44 32 02 48 01 f2 48 83 c2 03 48 89 15 f5 d9 00 00 80 fb 4b 0f 85 5b 06 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "NUITKA_ONEFILE_PARENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MacOS_HashBreaker_C_2147917118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HashBreaker.C!MTB"
        threat_id = "2147917118"
        type = "Trojan"
        platform = "MacOS: "
        family = "HashBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dump-generic-passwords" ascii //weight: 1
        $x_1_2 = "esrc/main.rsGet password" ascii //weight: 1
        $x_1_3 = "punlock-keychain" ascii //weight: 1
        $x_1_4 = "injecting/Documents/Addons.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

