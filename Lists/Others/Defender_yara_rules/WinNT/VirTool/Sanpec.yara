rule VirTool_WinNT_Sanpec_A_2147608368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Sanpec.gen!A"
        threat_id = "2147608368"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Sanpec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4b 60 8b 41 0c 2d 0c e0 22 00 56 57 c7 45 f8 04 00 00 c0 0f 84 ?? 01 00 00 6a 04 5a 2b c2}  //weight: 2, accuracy: Low
        $x_2_2 = {80 71 8b 40 38 68 00 20 00 00 05 00 c7 45}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 41 04 8d 14 24 cd 2e 83 c4 14 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 72 00 6f 00 63 00 50 00 61 00 6e 00 61 00 6d 00 61 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

