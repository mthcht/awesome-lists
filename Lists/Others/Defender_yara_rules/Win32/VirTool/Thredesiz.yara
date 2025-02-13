rule VirTool_Win32_Thredesiz_A_2147907211_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Thredesiz.A!MTB"
        threat_id = "2147907211"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Thredesiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 89 04 24 ?? ?? ?? ?? ?? 89 45 f0 83 7d f0 00 ?? ?? 8b 45 f0 89 44 24 04 c7 04 24 38 51 40 00 ?? ?? ?? ?? ?? 8b 45 f0 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 ff 0f 1f 00 ?? ?? ?? ?? ?? 83 ec 0c 89 45 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 45 ec 89 04 24 ?? ?? ?? ?? ?? 83 ec 14 89 45 e8 83 7d e8 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 10 00 00 00 00 c7 44 24 0c 01 00 00 00 c7 44 24 08 20 70 40 00 8b 45 e8 89 44 24 04 8b 45 ec 89 04 24 ?? ?? ?? ?? ?? 83 ec 14 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

