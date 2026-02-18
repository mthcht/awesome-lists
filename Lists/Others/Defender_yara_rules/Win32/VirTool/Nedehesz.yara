rule VirTool_Win32_Nedehesz_A_2147963242_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Nedehesz.A"
        threat_id = "2147963242"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedehesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 e4 f8 81 ec 74 06 00 00 a1 00 50 40 00 33 c4 89 84 24 70 06 00 00 53 56 57 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 64 a1 30 00 00 00 83 c4 04 8b 78 0c 83 c7 14 8b 37 3b f7}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 5f 5e 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3 8b 4e 10 85 c9 ?? ?? ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

