rule Backdoor_Win32_Xyligan_A_2147639903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xyligan.A"
        threat_id = "2147639903"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xyligan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 33 25 43 90 81 fb 08 00 72 f2 90 bb 00 10 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 1b 8a 84 0c 0c 01 00 00 04 14 88 84 0c 0c 02 00 00 34 06 88 44 0c 0c 41 3b ca 7c e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Xyligan_B_2147679101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xyligan.B"
        threat_id = "2147679101"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xyligan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 63 3a 5c 00 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "%s:*:Enabled:Microsoft" ascii //weight: 1
        $x_5_3 = {85 c0 74 31 8b 48 04 8b 54 24 0c 57 8b 78 08 8b 49 14 8b 32 8b d1 83 c0 14 c1 e9 02 f3 a5 8b ca 6a 00 83 e1 03 50 f3 a4}  //weight: 5, accuracy: High
        $x_5_4 = {8b 44 24 10 50 ff d3 b9 41 00 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 8d 94 24 ?? ?? ?? ?? f3 ab bf ?? ?? ?? 00 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 4c 24 24 33 ed 51 68 3f 00 0f 00 8d 94 24 ?? ?? ?? ?? 55 52 68 02 00 00 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

