rule Trojan_Win32_Desurou_A_2147628125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Desurou.A"
        threat_id = "2147628125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Desurou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 17 99 b9 00 01 00 00 f7 f9 8b 45 ?? 30 14 ?? 40 3b 45 ?? 89 45 ?? 7c e9}  //weight: 4, accuracy: Low
        $x_1_2 = {5b 77 79 62 68 6f 69 6e 69 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 6f 63 6b 68 6f 6d 65 70 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "sougousearchnav" ascii //weight: 1
        $x_1_5 = "googlesearchnav" ascii //weight: 1
        $x_1_6 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 83 7f 08 05 0f 82}  //weight: 1, accuracy: Low
        $x_1_7 = {00 63 73 79 73 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Desurou_B_2147630874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Desurou.B"
        threat_id = "2147630874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Desurou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 01 00 00 99 f7 f9 8b 45 ?? 30 10 8b 45 ?? 40 3b 45 ?? 89 45 ?? 7c df}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 83 7f 08 05 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {00 63 73 79 73 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Desurou_C_2147632194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Desurou.C"
        threat_id = "2147632194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Desurou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 33 01 66 03 f8 b8 01 00 00 00 70 ?? 66 03 c6 70 ?? 8b f0 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {64 00 65 00 73 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 00 6f 00 63 00 6b 00 68 00 6f 00 6d 00 65 00 70 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {20 00 5b 00 77 00 79 00 62 00 68 00 6f 00 69 00 6e 00 69 00 5d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

