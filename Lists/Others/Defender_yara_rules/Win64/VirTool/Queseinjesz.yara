rule VirTool_Win64_Queseinjesz_A_2147909555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Queseinjesz.A!MTB"
        threat_id = "2147909555"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Queseinjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 c4 80 ?? ?? ?? ?? ?? c7 45 dc 00 00 00 00 48 c7 45 d0 00 00 00 00 ?? ?? ?? ?? ?? ?? 89 c0 48 89 c1 ?? ?? ?? ?? ?? 48 89 05 f1 6f 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? c7 45 fc ff ff ff ff 83 7d fc 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 f0 49 89 d0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 b0 48 83 f8 ff ?? ?? 48 8b 45 b8 48 83 f8 ff ?? ?? b8 00 00 00 00 ?? ?? ?? ?? ?? 48 8b 45 b0 48 89 45 e8 48 8b 45 b8 48 89 45 e0 ?? ?? ?? ?? 48 8b 45 e8 c7 44 24 28 04 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? 41 b8 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 00 00 00 00 [0-18] 48 89 c1 [0-17] 41 89 c1 4c 8b 05 e7 6e 00 00 48 8b 55 d0 48 8b 45 e8 ?? ?? ?? ?? 48 89 4c 24 20 48 89 c1 ?? ?? ?? ?? ?? 89 45 fc 83 7d fc 00}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 00 00 00 [0-18] 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 d0 48 89 c2 48 8b 45 e0 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

