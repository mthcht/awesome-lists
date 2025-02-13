rule VirTool_Win32_Proholz_A_2147847730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Proholz.A!MTB"
        threat_id = "2147847730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Proholz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e0 8b 45 84 c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 54 24 08 c7 44 24 04 00 00 00 00 89 04 24 e8 ?? ?? ?? ?? 83 ec 14 89 45 d8 83 7d d8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 e8 51 40 00 e8 ?? ?? ?? ?? c7 04 24 12 00 00 00 e8 ?? ?? ?? ?? 83 ec 04 8b 45 88 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 c7 04 24 1c 52 40 00 e8 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 e0 8b 45 84 c7 44 24 10 00 00 00 00 89 54 24 0c 8b 55 dc 89 54 24 08 8b 55 d8 89 54 24 04 89 04 24 e8 ?? ?? ?? ?? 83 ec 14 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

