rule Backdoor_Win32_Ruperk_A_2147682665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ruperk.A"
        threat_id = "2147682665"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruperk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 75 70 65 72 62 6b 31 2e 72 75 00}  //weight: 2, accuracy: High
        $x_1_2 = {23 6e 6f 63 6d 64 00 00 23 64 65 73 74 72 75 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {23 72 75 6e 00 00 00 00 23 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {23 62 6f 74 5f 69 64 00 23 66 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 00 65 00 78 00 65 00 00 00 00 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_10_6 = {83 c0 01 89 45 f0 74 57 6a 05 8d 4d e0 51 e8 ?? ?? ?? ?? 83 c4 08 8d 55 e0 52 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f0 83 7d f0 00 74 31 68 ?? ?? ?? ?? 8d 45 e0 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 89 45 f0 83 7d f0 00 74 12 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

