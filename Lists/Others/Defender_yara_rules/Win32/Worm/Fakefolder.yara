rule Worm_Win32_Fakefolder_A_2147642696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fakefolder.A"
        threat_id = "2147642696"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefolder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 52 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 6a 01 6a 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 00 00 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 6c 61 79 65 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 69 6e 53 78 53 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Fakefolder_B_2147642697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fakefolder.B"
        threat_id = "2147642697"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefolder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 50 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 6a 01 6a 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 67 65 64 69 74 2e 65 78 65 00 2d 73 20}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 6c 61 79 65 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 69 6e 53 78 53 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

