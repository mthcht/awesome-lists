rule VirTool_Win32_Remeshelsz_A_2147900126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Remeshelsz.A"
        threat_id = "2147900126"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Remeshelsz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 a3 d8 61 40 00 a1 d0 61 40 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00 c7 44 24 04 d4 61 40 00 89 04 24 a1 ?? ?? ?? ?? ?? ?? 83 ec 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 08 44 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 62 40 00 ?? ?? ?? ?? ?? c7 05 00 62 40 ?? ?? ?? ?? ?? c7 05 2c 62 40 ?? ?? ?? ?? ?? a1 d0 61 40 00 a3 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

