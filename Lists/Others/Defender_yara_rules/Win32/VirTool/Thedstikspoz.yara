rule VirTool_Win32_Thedstikspoz_A_2147817503_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Thedstikspoz.A!MTB"
        threat_id = "2147817503"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Thedstikspoz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 dc 33 c0 89 45 ec 89 45 e0 8b 45 c0 2b c6 c6 45 fc 04 6a 04 89 45 c0 40 68 00 10 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 89 45 c4 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 a3 ?? ?? ?? ?? 0f 10 00 6a 07 50 c6 45 e4 b8 c6 45 e9 ff c6 45 ce e0 c7 45 e5 b0 11 40 00 c7 45 ec 00 00 00 00 c6 45 cf 00 0f ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 75 d4 68 20 15 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 ec 89 45 e0 c6 45 fc 04 89 45 c8 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 00 00 80 ff 70 04 66 0f 13 45 dc ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 45 c8 89 4d dc 89 45 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

