rule VirTool_Win32_Defnot_B_2147941250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Defnot.B"
        threat_id = "2147941250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defnot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 56 ff ?? ?? ?? ?? ?? 8b c8 83 f9 ff 89 0f 0f 95 c0 88 47 04 ?? ?? 6a 02 6a 00 6a 00 56 51 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 20 0b 45 24 6a 00 50 ff 75 18 ff 75 0c ff 75 1c ff 75 14 ff 75 08 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

