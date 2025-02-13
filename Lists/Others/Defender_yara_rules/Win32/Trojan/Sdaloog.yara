rule Trojan_Win32_Sdaloog_B_2147839764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdaloog.B"
        threat_id = "2147839764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdaloog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 00 50 45 00 00 0f 85 ?? ?? ?? ?? 6a 04 68 00 30 00 00 ff 75 50 ff 75 34 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c0 e0 04 2c 10 0a c3 32 c1 32 [0-5] 88 06 32 e8 [0-6] eb 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 41 04 8a 00 32 01 a2}  //weight: 1, accuracy: High
        $x_1_4 = {57 54 53 45 6e 75 6d 65 72 61 74 65 53 65 73 73 69 6f 6e 73 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdaloog_C_2147839765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdaloog.C"
        threat_id = "2147839765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdaloog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 6f 68 6e [0-16] 44 6f 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 41 4c 39 [0-16] 54 48 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {57 54 53 45 [0-16] 6e 75 6d 65 [0-16] 72 61 74 65}  //weight: 2, accuracy: Low
        $x_2_4 = {33 c0 ff d0 [0-32] 50 6a 01 6a 00 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_5 = {c0 e0 04 2c 10 0a c3 32 c1 32 c7 88 06 32 e8}  //weight: 2, accuracy: High
        $x_2_6 = {68 07 80 00 00 8b 41 04 8a 00 32 01 a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

