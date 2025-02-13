rule VirTool_Win32_DllInject_A_2147683452_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DllInject.A"
        threat_id = "2147683452"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 54 24 04 89 04 24 e8 ?? ?? ?? ?? ?? ?? 8b 3b 89 c6 8b 4d 10 f3 a4 8b 55 10 03 13 89 13 c6 02 e9 8b 0b 8d 51 01 29 d0 8b 75 10 8d 44 06 fc 89 41 01 89 f0 f7 d0 01 c2 89 13}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 4c 85 10 89 0c 82 40 39 d8 7c f4 8d 4b ff c1 e3 02 eb 07 89 d0 01 d8 ff 30 49 83 eb 04 85 c9 79 f2 8b 45 08 8b 18 89 d8 ff d0}  //weight: 3, accuracy: High
        $x_1_3 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {f7 7d 10 8b ?? 0c 8a 04 ?? 30 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

