rule VirTool_Win32_Redesz_A_2147955145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Redesz.A"
        threat_id = "2147955145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Redesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 04 00 00 ?? ?? ?? ?? ?? ?? 89 44 24 04 8b 45 f0 89 04 24 ?? ?? ?? ?? ?? 83 ec ?? 89 45 ec 83 7d ec 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 04 01 00 00 00 c7 04 24 ?? 00 00 00 ?? ?? ?? ?? ?? 83 ec 08 89 45 e8 81 7d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

