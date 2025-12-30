rule VirTool_Win32_Shelodesz_A_2147960264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelodesz.A"
        threat_id = "2147960264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 f0 8b 7d ec 3b c6 ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? 40 32 0a fe c1 88 0a 3b c6}  //weight: 1, accuracy: Low
        $x_1_2 = {51 52 57 e8 ?? ?? ?? ?? 83 c4 ?? ?? ?? 33 c0 2b d7 ?? ?? ?? 2b c8 8a 04 16 ?? ?? ?? 88 46 ff 83 e9 01 ?? ?? 68 d4 35 40 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

