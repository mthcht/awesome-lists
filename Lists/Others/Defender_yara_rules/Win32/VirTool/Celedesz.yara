rule VirTool_Win32_Celedesz_A_2147968576_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Celedesz.A"
        threat_id = "2147968576"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Celedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 ff 36 4b e8 ?? ?? ?? ?? 03 c7 68 e8 c2 48 00 50 e8 ?? ?? ?? ?? 83 c4 08 85 c0 ?? ?? 83 45 08 02 83 c6 04 85 db}  //weight: 1, accuracy: Low
        $x_1_2 = {50 c7 45 d4 00 00 00 00 c5 fa 7f 45 e0 c7 45 dc 00 00 00 00 ff ?? ?? ?? ?? ?? 8b f8 83 ff ff ?? ?? ?? ?? ?? ?? 6a 00 57 ff ?? ?? ?? ?? ?? 50 6a 00 89 45 d8 ff ?? ?? ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

