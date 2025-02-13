rule VirTool_Win64_Reflenjesz_A_2147909553_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Reflenjesz.A!MTB"
        threat_id = "2147909553"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflenjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 30 ?? ?? ?? ?? ?? 48 c7 45 f8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 45 f8 48 8b 45 f8 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 f8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 e0 48 01 c8 0f b7 00 66 25 ff 0f 0f b7 c0 01 d0 89 c0 48 89 45 d8 48 c7 45 b0 00 00 00 00 48 8b 55 38 48 8b 45 d8 48 01 d0 48 89 c3 [0-19] 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 49 89 d0 48 89 da 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 48 8b 45 40 41 b9 40 00 00 00 41 b8 00 30 00 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 38 48 8b 55 38 48 8b 45 48 48 8b 48 30 48 89 d0 48 29 c8 48 89 45 30 48 8b 45 48 8b 40 54 89 c2 48 8b 45 38 49 89 d0 48 8b 95 a0 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

