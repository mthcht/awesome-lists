rule VirTool_Win32_ShellDownloader_A_2147758796_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ShellDownloader.A!MTB"
        threat_id = "2147758796"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 0f 43 85 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 03 c6 50 e8 ?? ?? ?? ?? 83 8d e8 ?? ?? ?? 08 8d 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 10 6a 10 0f 43 85 ?? ?? ?? ?? 6a 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 00 20 00 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 8d 85 ?? ?? ?? ?? 68 00 20 00 00 50 56 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 02 00 00 00 66 89 85 80 bf ff ff 8b 46 0c 6a 10 8b 00 8b 00 89 85 84 bf ff ff 8d 85 ?? ?? ?? ?? 50 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

