rule VirTool_Win32_Shelpluk_A_2147817505_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelpluk.A!MTB"
        threat_id = "2147817505"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelpluk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 1c 86 40 3b c2 ?? ?? 8d ?? ?? ?? ?? ?? ?? 3b cf 73 0b 30 1c 31 8d ?? ?? 41 3b cf}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 06 8b 45 c4 2b c6 6a 04 89 45 c4 40 68 00 10 00 00 50 53 89 45 ec ff 15 ?? ?? ?? ?? 8b c8 89 4d c0 85 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 ff 75 c0 89 75 e4 68 70 1c 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b d8 85 db}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 40 6a 07 57 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8b 45 ec 89 07 66 8b 45 f0 66 89 47 04 8a 45 f6 88 47 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

