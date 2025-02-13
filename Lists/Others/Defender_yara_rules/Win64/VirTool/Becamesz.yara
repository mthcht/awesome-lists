rule VirTool_Win64_Becamesz_A_2147921770_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Becamesz.A!MTB"
        threat_id = "2147921770"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Becamesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 4d 10 48 89 55 18 44 89 45 20 48 8b 45 18 48 89 c2 [0-18] 48 8b 45 18 41 b8 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 18 41 b8 0a 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 45 b8 00 00 00 00 c7 45 b4 00 00 00 00 48 8b 05 60 d5 00 00 48 8b 50 28 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 c0 4d 89 c1 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? 85 c0 0f 94 c0 84 c0 ?? ?? 8b 4d b4 48 8b 55 b8 48 8b 05 2b d5 00 00 41 89 c8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 30 [0-18] 48 89 45 f8 ?? ?? ?? ?? ?? 48 89 05 86 d4 00 00 ?? ?? ?? ?? 48 89 c2 b9 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

