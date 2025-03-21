rule Trojan_Win64_ZamTamper_A_2147933900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZamTamper.A"
        threat_id = "2147933900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZamTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 00 61 00 6d 00 36 00 34 00 2e 00 73 00 79 00 73 00 00 00 2d 00 2d 00 6c 00 6f 00 6f 00 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5a 00 61 00 6d 00 6d 00 4f 00 63 00 69 00 64 00 65 00 00 00 2d 00 2d 00 70 00 69 00 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 61 69 6c 65 64 20 74 6f 20 74 65 72 6d 69 6e 61 74 65 20 70 72 6f 63 65 73 73 ?? ?? 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 64 72 69 76 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZamTamper_B_2147936636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZamTamper.B"
        threat_id = "2147936636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZamTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 2e 4c 6f 61 64 44 72 69 76 65 72 00 66 6d 74 2e 50 72 69 6e 74 66 00 66 6d 74 2e 50 72 69 6e 74 6c 6e 00 6d 61 69 6e 2e 4c 6f 61 64 44 72 69 76 65 72 2e 66 75 6e 63 33 00 6d 61 69 6e 2e 4c 6f 61 64 44 72 69 76 65 72 2e 66 75 6e 63 32 00 6d 61 69 6e 2e 4c 6f 61 64 44 72 69 76 65 72 2e 66 75 6e 63 31}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 61 6e 64 61 72 64 20 54 69 ?? 65 43 3a 5c 55 73 65 72 73 5c 70 75 62 6c 69 63 5c 7a 61 6d 36 34 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZamTamper_C_2147936637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZamTamper.C"
        threat_id = "2147936637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZamTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 4c 44 20 50 44 42 2e 01 00 00 00 44 3a 5c 44 65 76 5c 30 35 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 78 36 34 5c 52 65 6c ?? 61 73 65 5c 30 35 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

