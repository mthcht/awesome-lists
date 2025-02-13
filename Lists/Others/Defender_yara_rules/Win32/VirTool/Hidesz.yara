rule VirTool_Win32_Hidesz_A_2147849230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hidesz.A!MTB"
        threat_id = "2147849230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 18 8b 43 04 89 44 24 04 8b 03 89 04 24 e8 02 ?? ?? ?? 89 43 10 83 f8 ff 0f 84 87 08 00 00 89 44}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 03 8b b0 fc 00 00 00 e8 7d ?? ?? ?? 05 ec 29 00 00 2d 94 2a 00 00 89 04 24 ff ?? 51 85 c0 74 a7 0f bf 48 0a 8b 40 0c 8d 95}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 03 89 44 24 08 8b 45 d0 89 34 24 89 44 24 04 e8 61 ?? ?? ?? 85 c0 7e 4e 31}  //weight: 1, accuracy: Low
        $x_1_4 = {89 c7 89 44 24 04 89 34 24 ff ?? ?? 31 c0 51 51 89 44 24 08 89 74 24 04 8b 45 08 89 04 24 ff 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

