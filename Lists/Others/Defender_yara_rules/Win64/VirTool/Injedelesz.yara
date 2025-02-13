rule VirTool_Win64_Injedelesz_A_2147916126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injedelesz.A!MTB"
        threat_id = "2147916126"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injedelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 45 f8 49 ff c0 c7 44 24 20 04 00 00 00 33 d2 41 b9 00 10 00 00 48 8b ce ?? ?? ?? ?? ?? ?? 4c 8b f0 48 85 c0 ?? ?? ?? ?? ?? ?? 66 89 44 24 76 48 c7 44 24 78 0e 00 00 00 48 c7 45 80 0f 00 00 00 f2 0f 10 05 41 28 00 00 f2 0f 11 44 24 68 8b 05 3d 28 00 00 89 44 24 70 0f b7 05 36 28 00 00 66 89 44 24 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 7d 00 0f 4c 0f 47 45 e8 4c 8b 4d f8 49 ff c1 48 89 5c 24 20 49 8b d6 48 8b ce ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 5c 24 30 89 5c 24 28 4c 89 74 24 20 4d 8b cf 45 33 c0 33 d2 48 8b ce ?? ?? ?? ?? ?? ?? 4c 8b f8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 5c 24 30 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 80 48 8b 4e 08 ?? ?? ?? ?? ?? ?? 48 83 f8 ff ?? ?? ?? ?? ?? ?? 89 5c 24 74 48 c7 44 24 78 0b 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {44 8b c0 33 d2 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? 48 8b f0 48 85 c0 ?? ?? ?? ?? ?? ?? 89 5c 24 74 48 c7 44 24 78 0b 00 00 00 48 c7 45 80 0f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

