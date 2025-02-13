rule VirTool_Win64_Refledelesz_A_2147910499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Refledelesz.A!MTB"
        threat_id = "2147910499"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Refledelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 9c 24 b0 03 00 00 ?? ?? ?? ?? ?? ?? ?? 4c 89 ac 24 88 03 00 00 45 33 ed 44 89 ad f0 01 00 00 c7 85 08 02 00 00 ?? ?? ?? ?? c7 85 0c 02 00 00 ?? ?? ?? ?? c7 85 10 02 00 00 ?? ?? ?? ?? 66 c7 85 14 02 00 00 ?? 00 c7 85 00 02 00 00 ?? ?? ?? ?? 66 c7 85 04 02 00 00 ?? 00 c7 44 24 60 [0-16] 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 10 00 00 41 b8 40 00 00 00 48 8b cb ?? ?? ?? ?? ?? ?? 85 c0 [0-17] 8b 44 24 60 ?? ?? ?? ?? ?? ?? ?? 89 03 ba 00 10 00 00 44 8b 85 f0 01 00 00 48 8b cb}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b c3 66 48 0f 7e f2 48 8b c8 4c 8b f0 ?? ?? ?? ?? ?? 4d 63 7e 3c 33 c9 4d 03 fe 41 b8 00 30 00 00 ?? ?? ?? ?? 41 8b 57 50 ?? ?? ?? ?? ?? ?? 45 8b 47 54 49 8b d6 48 8b c8 48 8b f8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 4c f4 70 ?? ?? ?? ?? ?? ?? ?? 4d 8b c7 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 49 83 c7 06 48 ff c6 48 83 fe 4d ?? ?? 66 0f 6f 05 ce 31 00 00 4d 8b fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

