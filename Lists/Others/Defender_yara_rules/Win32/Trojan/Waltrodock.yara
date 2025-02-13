rule Trojan_Win32_Waltrodock_A_2147652395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waltrodock.A"
        threat_id = "2147652395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 6b 74 44 6f 77 6e 6c 6f 61 64 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 6f 66 74 75 72 6c 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 02 33 c0 41 81 f9 04 01 00 00 7c d9 1a 00 8a 90 ?? ?? ?? ?? 8a 9c 0c ?? ?? ?? ?? 32 da 40 83 f8 10 88 9c 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waltrodock_B_2147652396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waltrodock.B"
        threat_id = "2147652396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RktDriver.pdb" ascii //weight: 1
        $x_1_2 = {8d b0 80 16 01 00 33 db f3 a6 74 07 40 3b c2 7e e7}  //weight: 1, accuracy: High
        $x_1_3 = {7d 2a 8d 43 ff 3b c8 8d 04 89 8d 34 c2 74 05 8b 46 34 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waltrodock_C_2147658613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waltrodock.C"
        threat_id = "2147658613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "softurl%d" ascii //weight: 1
        $x_1_2 = {5c 56 65 72 73 69 6f 6e 4b 65 79 2e 69 6e 69 [0-12] 66 75 63 6b}  //weight: 1, accuracy: Low
        $x_4_3 = {32 da 40 83 f8 10 88 [0-6] 75 02 33 c0 41 81 f9 04 01 00 00 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

