rule VirTool_Win32_Tinmet_A_2147755735_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tinmet.A"
        threat_id = "2147755735"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinmet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 89 75 fc ff d3 a1 ?? ?? ?? ?? 6a 40 68 00 10 00 00 83 c0 05 50 [0-6] ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 45 fc 80 33 00 00 50 6a 1f 56 ff 15 ?? ?? ?? ?? 53 53 53 53 56 ff 15 ?? ?? ?? ?? 85 c0 75 07 68 ?? ?? ?? ?? eb ?? 6a 40 68 00 10 00 00 68 00 00 40 00 53 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {83 c4 0c a3 ?? ?? ?? 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

