rule VirTool_Win32_ClipInject_A_2147832007_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ClipInject.A"
        threat_id = "2147832007"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 05 51 62 00 00 8b 95 98 00 00 00 49 89 d0 48 8b 55 10 48 8d ?? ?? 48 c7 44 24 50 00 00 00 00 48 c7 44 24 48 00 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 4c 89 44 24 20 49 89 d1 41 b8 00 00 00 00 ba ff ff 1f 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 0c 8b 45 fc 01 d0 89 85 98 00 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 98 00 00 00 48 89 45 e8 c7 45 00 53 00 00 00 48 8b 05 c5 62 00 00 48 8b 4d 10 49 89 ea}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 14 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 8d}  //weight: 1, accuracy: High
        $x_1_4 = {55 48 89 e5 48 83 c4 80 48 89 4d 10 48 89 55 18 48 c7 45 f0 00 00 00 00 c7 45 fc 00 00 00 00 c7 45 ec 00 00 00 00 48 8b 05 ef 66 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

