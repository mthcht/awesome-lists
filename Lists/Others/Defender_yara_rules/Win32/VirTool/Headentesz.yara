rule VirTool_Win32_Headentesz_A_2147898254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Headentesz.A!MTB"
        threat_id = "2147898254"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Headentesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 84 e1 41 00 ?? ?? 83 ec ?? 89 45 e8 c7 04 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ec ?? a1 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 89 54 24 ?? c7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e4 8b 85}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 ec c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 ?? ?? ?? ?? ?? ?? 83 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

