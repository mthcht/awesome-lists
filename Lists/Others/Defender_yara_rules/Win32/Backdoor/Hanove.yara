rule Backdoor_Win32_Hanove_A_2147650425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hanove.A"
        threat_id = "2147650425"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 70 6c 6f 61 64 64 69 72 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 6e 61 6d 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 10 8b c8 8b 42 0c ff d0 83 c0 10 89 07 6a 04 68 ?? ?? ?? ?? 8d 4c 24 14 c7 44 24 18 01 00 00 00 e8 ?? ?? ?? ?? 6a 02 68 ?? ?? ?? ?? 8d 4c 24 14 e8 ?? ?? ?? ?? 6a 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

