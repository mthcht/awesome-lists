rule VirTool_Win64_Helehesz_A_2147918373_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Helehesz.A!MTB"
        threat_id = "2147918373"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Helehesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 78 48 8b 05 c5 45 00 00 48 33 c4 48 89 44 24 60 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 48 48 c7 44 24 38 00 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 50 00 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 ba 01 00 00 00 [0-18] 48 89 44 24 38 48 83 7c 24 38 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 15 f1 52 00 00 8b 0d db 52 00 00 ?? ?? ?? ?? ?? c7 44 24 28 04 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? ?? 48 8b 4c 24 68 ?? ?? ?? ?? ?? 89 44 24 60 83 7c 24 60 00 ?? ?? 48 83 7c 24 78 00 ?? ?? 8b 54 24 60 [0-18] b8 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 15 ff 51 00 00 8b 0d e9 51 00 00 ?? ?? ?? ?? ?? 48 c7 44 24 50 00 00 00 00 48 c7 44 24 48 00 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 8b 44 24 78 48 89 44 24 20 4c 8b 4c 24 68 45 33 c0 ba ff ff 1f 00 [0-19] 89 44 24 60 83 7c 24 60 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 24 00 00 00 00 [0-32] 48 8b c8 ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 83 7c 24 40 00 ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 [0-18] 33 c0 ?? ?? ?? ?? ?? 48 6b 44 24 78 10 48 89 44 24 38 ?? ?? ?? ?? ?? ?? 4c 8b 44 24 38 33 d2 48 8b c8 ?? ?? ?? ?? ?? ?? 48 89 44 24 30 48 83 7c 24 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

