rule VirTool_Win32_Disedr_B_2147930831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Disedr.B"
        threat_id = "2147930831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Disedr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 00 00 00 00 50 6a 02 6a 00 68 ?? ?? ?? ?? 68 02 00 00 80 ff 15 04 30 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 65 f4 00 ?? ?? ?? 83 65 f8 00 50 ff ?? ?? ?? ?? ?? 8b 45 f8 33 45 f4 89 45 fc ff ?? ?? ?? ?? ?? 31 45 fc ff ?? ?? ?? ?? ?? 31 45 fc ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c9 03 c7 8b bd e4 fb ff ff d1 e8 51 51 51 51 ff b5 dc fb ff ff 66 89 4c 47 10 57 68 a4 00 09 00 53 ff ?? ?? ?? ?? ?? 57 6a 00 8b f0 ff ?? ?? ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

