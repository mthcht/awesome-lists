rule VirTool_Win64_Bewamesz_A_2147921771_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bewamesz.A!MTB"
        threat_id = "2147921771"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bewamesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 48 81 ec a8 00 00 00 [0-18] b8 00 00 00 00 b9 0e 00 00 00 48 89 d7 f3 48 ab c7 45 a0 70 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 45 b0 48 8b 05 96 cc 09 00 ?? ?? 48 8b 00 48 8b 00 48 89 45 b8 48 c7 45 a8 00 00 00 00 c7 45 d0 00 00 00 00 ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 ec 50 ?? ?? ?? ?? 48 89 44 24 20 41 b9 02 00 00 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 83 7d fc 00 ?? ?? ?? ?? ?? ?? c7 45 ec 00 00 00 00 48 8b 4d f0 c7 44 24 28 04 00 00 00 ?? ?? ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 41 b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 30 41 b9 40 00 00 00 41 b8 00 10 00 00 ba c4 01 00 00 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f8 48 8b 45 f8 41 b8 c4 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 f8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 45 30 48 89 44 24 40 c7 44 24 38 28 00 00 00 c7 44 24 30 cc 01 00 00 c7 44 24 28 14 00 00 00 c7 44 24 20 14 00 00 00 41 b9 00 00 00 50 [0-20] b9 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

