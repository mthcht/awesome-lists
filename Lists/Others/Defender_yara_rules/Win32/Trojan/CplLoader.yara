rule Trojan_Win32_CplLoader_A_2147789204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CplLoader.A"
        threat_id = "2147789204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CplLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-255] 2e 00 77 00 73 00 66 00 3a 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 [0-255] 2e 00 77 00 73 00 66 00}  //weight: 10, accuracy: Low
        $x_10_2 = {77 73 63 72 69 70 74 [0-255] 2e 77 73 66 3a 2e 2e 2f 2e 2e 2f [0-255] 2e 77 73 66}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CplLoader_A_2147789204_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CplLoader.A"
        threat_id = "2147789204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CplLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-255] 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-5] 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 72 00 75 00 6e 00 64 00 4c 00 4c 00 [0-5] 2e 00 63 00 70 00 6c 00 3a 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 [0-255] 2e 00 69 00 6e 00 66 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 75 6e 64 6c 6c 33 32 [0-255] 73 68 65 6c 6c 33 32 2e 64 6c 6c [0-5] 63 6f 6e 74 72 6f 6c 5f 72 75 6e 64 4c 4c [0-5] 2e 63 70 6c 3a 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 61 70 70 64 61 74 61 2f 6c 6f 63 61 6c 2f [0-255] 2e 69 6e 66}  //weight: 10, accuracy: Low
        $x_10_3 = {63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 [0-255] 2e 00 63 00 70 00 6c 00 3a 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 2e 00 2e 00 [0-255] 2f 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 [0-255] 2e 00 69 00 6e 00 66 00}  //weight: 10, accuracy: Low
        $x_10_4 = {63 6f 6e 74 72 6f 6c 2e 65 78 65 [0-255] 2e 63 70 6c 3a 2e 2e 2f 2e 2e 2f 2e 2e [0-255] 2f 61 70 70 64 61 74 61 2f 6c 6f 63 61 6c 2f [0-255] 2e 69 6e 66}  //weight: 10, accuracy: Low
        $x_10_5 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-255] 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-5] 23 00 34 00 34 00 [0-5] 2e 00 63 00 70 00 6c 00 3a 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 [0-255] 2e 00 69 00 6e 00 66 00}  //weight: 10, accuracy: Low
        $x_10_6 = {72 75 6e 64 6c 6c 33 32 [0-255] 73 68 65 6c 6c 33 32 2e 64 6c 6c [0-5] 23 34 34 [0-5] 2e 63 70 6c 3a 2e 2e 2f 2e 2e 2f 2e 2e 2f 61 70 70 64 61 74 61 2f 6c 6f 63 61 6c 2f [0-255] 2e 69 6e 66}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

