rule VirTool_Win32_Smestesz_A_2147907210_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Smestesz.A!MTB"
        threat_id = "2147907210"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Smestesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 c7 44 24 04 cc 01 00 00 c7 04 24 00 00 00 00 ?? ?? ?? ?? ?? 83 ec 10 89 45 e4 c7 04 24 94 50 40 00 ?? ?? ?? ?? ?? 8b 45 e4 bb 20 70 40 00 ba cc 01 00 00 8b 0b 89 08 8b 4c 13 fc 89 4c 10 fc ?? ?? ?? 83 e7 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 83 ec 38 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 80 8b 45 08 89 04 24 ?? ?? ?? ?? ?? 83 ec 1c 89 45 f4 83 7d f4 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

