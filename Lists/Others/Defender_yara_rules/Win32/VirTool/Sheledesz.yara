rule VirTool_Win32_Sheledesz_A_2147961815_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sheledesz.A"
        threat_id = "2147961815"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sheledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 50 31 40 00 c7 44 24 2c 00 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 38 00 00 00 00 c7 44 24 3c 00 00 00 00 c7 44 24 28 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 10 33 c9 33 d2 85 f6 ?? ?? 8a 44 0c 0c 30 04 17 ?? ?? ?? 42 83 f8 03 1b c9 23 c8 3b d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

