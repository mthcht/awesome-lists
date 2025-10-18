rule VirTool_Win32_Midelesz_A_2147955443_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Midelesz.A"
        threat_id = "2147955443"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Midelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f4 83 7d f4 00 [0-34] 83 c4 04 68 e8 03 00 00 ?? ?? ?? ?? ?? ?? 6a 04 68 00 30 00 00 8b 55 f8 52 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 8b 14 01 52 [0-16] 83 c4 08 68 e8 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? 51 ba 04 00 00 00 c1 e2 00 8b 45 0c 8b 0c 10 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

