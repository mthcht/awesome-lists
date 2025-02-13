rule VirTool_Win32_Revesekasz_A_2147906326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Revesekasz.A!MTB"
        threat_id = "2147906326"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Revesekasz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 24 ?? ?? ?? 89 44 24 20 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 8b 45 0c 89 44 24 04 c7 04 24 00 00 00 00 a1 5c 81 40 00 ?? ?? 83 ec 28}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 24 82 40 00 ?? ?? 83 ec 18 89 45 f0 83 7d f0 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 e8 89 55 ec c7 45 f4 01 00 00 00 8b 45 e8 8b 55 ec 09 d0 85 c0 ?? ?? 8b 45 e8 8b 55 ec 89 44 24 0c 89 54 24 10 8b 45 0c 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

