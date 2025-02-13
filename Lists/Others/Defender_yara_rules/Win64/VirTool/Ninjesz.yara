rule VirTool_Win64_Ninjesz_A_2147850799_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ninjesz.A!MTB"
        threat_id = "2147850799"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ninjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 20 41 b9 20 00 00 00 4c 8d 84 ?? ?? ?? ?? ?? 48 8d 94 ?? ?? ?? ?? ?? 48 8b 8c 24 a8 00 00 00 e8 37 ?? ?? ?? 33 d2 48 8b 8c 24 c0 01 00 00 ff 15 ?? ?? ?? ?? 33 c0 48 8b 8c 24 20 02 00 00 48}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 84 24 d0 00 00 00 48 c7 84 24 a8 00 00 00 ff ff ff ff c6 84 24 f0 01 00 00 77 c6 84 24 f1 01 00 00 69 c6 84 24 f2 01 00 00 6e c6 84 24 f3 01 00 00 64 c6 84 24 f4 01 00 00 6f c6 84 24 f5 01 00 00 77 c6 84 24 f6 01 00 00 73 c6 84 24 f7 01 00 00 2e c6 84 24 f8 01 00 00 73 c6 84 24 f9 01 00 00 74 c6 84 24 fa 01 00 00 6f c6 84 24 fb 01 00 00 72 c6 84 24 fc 01 00 00 61 c6 84 24 fd 01 00 00 67 c6 84 24 fe 01 00 00 65 c6 84 24 ff 01 00 00 2e c6 84 24 00 02 00 00 64 c6 84 24 01 02 00 00 6c c6 84 24 02 02 00 00 6c c6 84 24 03 02 00 00 00 48 8d 8c ?? ?? ?? ?? ?? ff 94 ?? ?? ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 84 24 10 01 00 00 e8 a6 ?? ?? ?? 48 8b 40 60 48 89 84 24 f0 00 00 00 48 8b 84 24 f0 00 00 00 48 8b 40 18 48 89 84 24 f8 00 00 00 48 c7 44 24 48 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 44 24 30 ff c0 89 44 24 30 0f b7 54 24 30 48 8b 8c 24 c0 00 00 00 e8 7e ?? ?? ?? 66 89 84 24 c8 00 00 00 0f b7 84 24 c8 00 00 00 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

