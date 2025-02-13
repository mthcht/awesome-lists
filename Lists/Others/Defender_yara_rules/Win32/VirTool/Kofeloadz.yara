rule VirTool_Win32_Kofeloadz_A_2147828025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Kofeloadz.A!MTB"
        threat_id = "2147828025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kofeloadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6b c2 28 48 8b 54 24 38 48 8b 7c 24 60 31 c9 4c 89 d6 4c 89 54 24 28 41 b9 04 00 00 00 41 b8 00 30 10 00 48 c1 e6 04 48 8d ?? ?? ?? 48 01 f7 8b 50 10 48 89 44 24 48 48 89 57 08 ?? ?? ?? 48 8b 54 24 48 4c 8b 54 24 28 48 89 07 48 8b 44 24 60 8b 4a 10 49 ff c2 48 8b 04 30 8b 72 14 48 89 c7 48 01 de}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 54 24 38 48 89 d3 4c 89 c5 4d 89 ce 48 89 54 24 40 0f b7 52 02 b9 40 00 00 00 4c 8d ?? ?? ?? 48 c1 e2 04 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 02 48 8b 4c 24 20 48 8b 54 24 38 41 b8 04 00 00 00 b8 40 00 00 00 44 0f 45 c0 48 03 ?? ?? ?? ?? ?? 48 89 4b 08 49 89 d9 48 89 53 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

