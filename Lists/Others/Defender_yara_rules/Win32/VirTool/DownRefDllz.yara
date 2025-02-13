rule VirTool_Win32_DownRefDllz_B_2147839553_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DownRefDllz.B!MTB"
        threat_id = "2147839553"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DownRefDllz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 70 00 42 00 8b 45 e8 50 8b 4d d0 51 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b f4 8d 85 ?? ?? ?? ?? 50 8d 8d ?? ?? ?? ?? 51 6a 00 6a 02 68 78 ff 41 00 68 ?? ff 41 00 68 02 00 00 80 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 85 b0 fd ff ff 8b 85 b0 fd ff ff 89 85 f4 f7 ff ff 81 bd f4 f7 ff ff 6f 07 00 00 74 21}  //weight: 1, accuracy: High
        $x_1_4 = {8b f4 8d 45 ?? 50 8b 4d c0 51 8b 55 a8 52 8b 85 78 ff ff ff 50 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 0f b7 45 0c 50 8b 4d 08 51 8b 55 90 52 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

