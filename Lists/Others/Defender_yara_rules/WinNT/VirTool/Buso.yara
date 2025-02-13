rule VirTool_WinNT_Buso_A_2147599387_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Buso.A"
        threat_id = "2147599387"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Buso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0f 8b 4d 10 8a 11 80 f2 ?? 88 10 40 41 4e 75 f4 80 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 08 c7 02 10 00 00 c0 eb 57 56 8b 75 10 3b f7 74 48 39 7d 14 74 43 8b 4d 14 c1 e9 02 8b c1 c1 e0 02 3b 45 14 75 33 fa 0f 20 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

