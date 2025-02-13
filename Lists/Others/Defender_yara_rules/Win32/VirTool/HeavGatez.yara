rule VirTool_Win32_HeavGatez_B_2147839556_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/HeavGatez.B!MTB"
        threat_id = "2147839556"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HeavGatez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0d 50 b2 41 00 89 41 56 89 51 5a a1 50 b2 41 00 83 c0 6c 8b 0d 50 b2 41 00 89 41 66 8b f4 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0d 50 b2 41 00 89 41 12 89 51 16 8b 45 10 33 c9 8b 15 50 b2 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {a1 50 b2 41 00 03 45 d8 8b 4d d8 8a 91 60 b0 41 00 88 10 eb dc}  //weight: 1, accuracy: High
        $x_1_4 = {52 50 6a 07 8b 45 d4 50 8b 4d d0 51 e8}  //weight: 1, accuracy: High
        $x_1_5 = {6a 64 6a 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8b f4 8d 85 ?? ?? ?? ?? 50 68 04 01 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

