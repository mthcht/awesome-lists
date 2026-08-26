rule VirTool_Win32_Megesz_A_2147977018_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Megesz.A"
        threat_id = "2147977018"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Megesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 79 01 05 ?? ?? 89 0d c4 30 40 00 80 3f e9 ?? ?? 33 f6 8b d6 c1 e2 05 03 d7 80 3a 4c ?? ?? 33 c0 80 3c 10 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 8b d7 c1 e0 05 2b d0 80 3a 4c ?? ?? 33 c0 80 3c 10 b8 ?? ?? ?? ?? ?? 40 83 f8 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

