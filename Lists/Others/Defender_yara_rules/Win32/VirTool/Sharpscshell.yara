rule VirTool_Win32_Sharpscshell_A_2147910767_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sharpscshell.A!MTB"
        threat_id = "2147910767"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharpscshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 89 04 24 ?? ?? ?? ?? ?? 83 ec 18 89 45 d0 83 7d d0 00 ?? ?? ?? ?? ?? ?? ?? 89 44 24 04 [0-18] c7 04 24 00 00 00 00 [0-34] 89 c2 ?? ?? ?? 89 44 24 08 c7 44 24 04 ff 00 0f 00 89 14 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 d0 00 00 00 00 8b 45 c0 89 04 24 ?? ?? ?? ?? ?? 83 ec 04 89 45 d0 83 7d d0 00 ?? ?? ?? ?? ?? ?? ?? 89 44 24 04 [0-18] c7 04 24 00 00 00 00 ?? ?? ?? ?? ?? c7 44 24 08 3f 00 0f 00 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 f4 89 04 24}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 cc 89 44 24 04 [0-18] 8b 45 e4 89 44 24 04 [0-18] c7 44 24 08 ff 01 0f 00 8b 45 e4 89 44 24 04 8b 45 cc 89 04 24}  //weight: 1, accuracy: Low
        $x_1_4 = {89 44 24 04 c7 04 24 40 00 00 00 ?? ?? ?? ?? ?? 83 ec 08 89 45 f0 c7 45 d0 00 00 00 00 ?? ?? ?? 89 44 24 0c 8b 45 ec 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 c8 89 04 24 ?? ?? ?? ?? ?? 83 ec 10 89 45 d0 8b 45 f0 8b 40 0c 89 45 e8 8b 45 e8 89 44 24 04}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 c8 89 04 24 ?? ?? ?? ?? ?? 83 ec 2c 89 45 d0 83 7d d0 00 ?? ?? ?? ?? ?? ?? ?? 89 44 24 04 [0-18] c7 04 24 00 00 00 00 ?? ?? ?? ?? ?? 8b 45 e0 89 44 24 04 [0-18] c7 45 d0 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8b 45 c8 89 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

