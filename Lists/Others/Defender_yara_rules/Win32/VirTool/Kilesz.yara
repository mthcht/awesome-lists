rule VirTool_Win32_Kilesz_A_2147961811_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Kilesz.A"
        threat_id = "2147961811"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 00 b9 03 01 00 00 89 d7 f3 ab c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 c0 c7 04 24 f4 50 40 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 0c 04 00 00 ?? ?? ?? ?? ?? ?? 89 44 24 08 c7 44 24 04 1c 20 22 00 8b 45 f0 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

