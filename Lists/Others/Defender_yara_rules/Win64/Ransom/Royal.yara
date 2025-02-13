rule Ransom_Win64_Royal_ZZ_2147834986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Royal.ZZ"
        threat_id = "2147834986"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Royal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {48 89 00 48 89 40 08 48 89 43 08 ff 15 ?? ?? ?? ?? 45 33 c0 8d 56 01 8d 4e 02 ff 15 ?? ?? ?? ?? 48 8b f8 48 83 f8 ff 74 6c 48 89 74 24 40 48 8d 4c 24 60 48 89 74 24 38 48 8d 83 18 60 00 00 48 89 4c 24 30 44 8d 4e 10 c7 44 24 28 08 00 00 00 4c 8d 44 24 50 48 8b cf 48 89 44 24 20 ba 06 00 00 c8 c7 44 24 50 b9 07 a2 25 c7 44 24 54 f3 dd 60 46 c7 44 24 58 8e e9 76 e5 c7 44 24 5c 8c 74 06 3e ff 15 ?? ?? ?? ?? 85}  //weight: 10, accuracy: Low
        $x_10_3 = {c7 41 0c 02 00 00 00 0f 57 c0 48 c7 01 ff ff ff ff 48 8d 52 30 89 71 08 48 8d 49 30 0f 11 42 d0 0f 11 42 e0 48 83 e8 01 75 d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Royal_MKP_2147835068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Royal.MKP!MTB"
        threat_id = "2147835068"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 8d 44 24 78 89 5c 24 70 48 89 44 24 30 4c 8d 44 24 68 48 8d 44 24 7c 89 5c 24 7c 48 89 44 24 28 48 8d 4d 48 8d 8d 44 24 70 89 5c 24 78 41 b9 ?? ?? ?? ?? 48 89 44 24 20 ba ?? ?? ?? ?? 48 89 5c 24 68}  //weight: 11, accuracy: Low
        $x_1_2 = "ENCRYPTED" ascii //weight: 1
        $x_1_3 = "README.TXT" ascii //weight: 1
        $x_1_4 = "tor browser" ascii //weight: 1
        $x_1_5 = ".royal" ascii //weight: 1
        $x_1_6 = "mozilla" ascii //weight: 1
        $x_1_7 = "ENCRYPTED PRIVATE KEY" ascii //weight: 1
        $x_1_8 = "Decrypting - %s" ascii //weight: 1
        $x_1_9 = "uncompressed" ascii //weight: 1
        $x_1_10 = "load_iv" ascii //weight: 1
        $x_1_11 = "END RSA PRIVATE KEY" ascii //weight: 1
        $x_1_12 = "BEGIN RSA PRIVATE KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

