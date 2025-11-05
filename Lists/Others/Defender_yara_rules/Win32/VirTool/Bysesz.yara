rule VirTool_Win32_Bysesz_A_2147956757_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bysesz.A"
        threat_id = "2147956757"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bysesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 83 c4 ?? 33 c0 89 4c 24 10 80 3c 06 b8 ?? ?? 83 f8 1c ?? ?? 40 83 f8 20 ?? ?? 33 c0 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8c 24 1c 05 00 00 8b 84 24 74 05 00 00 89 01 66 8b 84 24 78 05 00 00 66 89 41 04 ?? ?? ?? ?? ?? ?? ?? 50 ff b4 24 5c 05 00 00 ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? 50 6a ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

