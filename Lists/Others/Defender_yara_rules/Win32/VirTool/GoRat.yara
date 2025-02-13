rule VirTool_Win32_GoRat_A_2147772158_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/GoRat.A!MTB"
        threat_id = "2147772158"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 58 48 89 6c 24 50 48 8d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 84 00 48 8b 05 fa d2 1c 00 48 8b 0d 33 46 11 00 48 89 04 24 0f 57 c0 0f 11 44 24 08 48 89 4c 24 18 48 8b 44 24 60 48 89 44 24 20 0f 11 44 24 28 e8 ?? ?? ?? ?? 48 8b 44 24 38 48 85 c0 74 1f 48 8b 0d d5 d2 1c 00 48 89 0c 24 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 6c 24 50 48 83 c4 58 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {65 48 8b 0c 25 28 00 00 00 48 8b 89 00 00 00 00 48 3b 61 10 0f 86 2e 01 00 00 48 83 ec 48 48 89 6c 24 40 48 8d ?? ?? ?? 48 8b 44 24 58 48 83 f8 02 0f ?? ?? ?? ?? ?? 0f 57 c0 0f 11 44 24 30 48 83 c0 fd 48 89 c1 48 f7 d8 48 c1 f8 3f 48 83 e0 03 48 8b 54 24 50 48 01 d0 48 89 44 24 30 48 89 4c 24 38 48 8d ?? ?? ?? ?? ?? 48 89 04 24 48 c7 44 24 08 02 00 00 00 48 8d ?? ?? ?? 48 89 44 24 10 48 c7 44 24 18 01 00 00 00 48 c7 44 24 20 01 00 00 00 e8 c8 9d ff ff 48 8b 44 24 28 48 89 04 24 e8 1a c7 ff ff 48 8b 44 24 08 48 8b 4c 24 10 48 c7 04 24 00 00 00 00 48 89 44 24 08 48 89 4c 24 10 e8 d9 92 f4 ff 48 8b 44 24 18 48 8b 4c 24 20 48 89 44 24 60 48 89 4c 24 68 48 8b 6c 24 40 48 83 c4 48 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "Go build ID: \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

