rule VirTool_WinNT_Siapag_A_2147609743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Siapag.gen!A"
        threat_id = "2147609743"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Siapag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 57 60 b8 ?? 00 00 00 bb ?? 00 00 00 90 90 90 61}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 e0 8b 30 a1 90 08 01 00 39 70 08 77 09 c7 45 e4 0d 00 00 c0 eb}  //weight: 10, accuracy: High
        $x_1_3 = "\\Device\\RESSDT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

