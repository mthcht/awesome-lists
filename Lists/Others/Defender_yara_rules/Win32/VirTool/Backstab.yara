rule VirTool_Win32_Backstab_B_2147899793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Backstab.B"
        threat_id = "2147899793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Backstab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 08 c7 44 24 38 00 00 00 00 ff ?? 50 ff ?? ?? ?? 40 00 85 c0 ?? ?? ?? ?? ?? ?? 89 74 24 3c 50 6a 04 ?? ?? ?? ?? c7 44 24 50 04 00 00 00 50 6a 14 ff 74 24 44 ff ?? ?? ?? 40 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 10 ?? ?? ?? ?? 50 6a 00 ff 74 24 48 ff ?? ?? ?? 40 00 ff 74 24 34 85 c0 a1 74 40 40 00 ?? ?? ff ?? be 04 47 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {bf 01 00 00 00 89 7c 24 18 ff ?? ?? ?? 40 00 83 c4 04 89 44 24 58 50 6a 00 68 00 10 00 00 ff ?? ?? ?? 40 00 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c4 89 84 24 c4 08 00 00 8b 45 0c 0f 10 ?? ?? ?? ?? 00 56 57 89 44 24 1c a1 ?? ?? ?? 00 68 f4 01 00 00 89 84 24 c4 04 00 00 ?? ?? ?? ?? ?? ?? ?? 6a 00 50 0f 11 84 24 bc 04 00 00 e8 ?? ?? 00 00 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

