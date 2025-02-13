rule VirTool_Win32_Gosam_A_2147818519_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Gosam.A!MTB"
        threat_id = "2147818519"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gosam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f4 6a 0c 8d ?? ?? 50 e8 ?? ?? ?? ?? c7 45 f4 0c 00 00 00 c7 45 fc 01 00 00 00 6a 00 8d ?? ?? 50 68 4c 37 40 00 68 40 37 40 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 c4 f8 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 33 c9 ?? ?? 51 6a 00 8d ?? ?? 50 6a 00 6a 00 6a 00 ff 35 40 37 40 00 e8 ?? ?? ?? ?? 0b c0 75 04 eb 27 eb 0f 83 7d fc 00 74 09 8b 45 f8 03 45 fc 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 f8 00 00 00 00 8b 4d 0c 41 51 51 e8 ?? ?? ?? ?? 89 45 f8 59 51 ff 75 f8 e8 ?? ?? ?? ?? 6a 00 8d ?? ?? 50 ff 75 0c ff 75 f8 ff 35 40 37 40 00 e8 ?? ?? ?? ?? 0b c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b ec 6a 04 68 00 30 00 00 ff 75 08 6a 00 e8 ?? ?? ?? ?? 0b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

