rule VirTool_WinNT_Loodir_A_2147689969_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Loodir.A"
        threat_id = "2147689969"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Loodir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 13 00 00 00 bf ?? ?? ?? ?? f3 a5 0f b7 0d ?? ?? ?? ?? 81 f9 55 aa 00 00 74 11 b9 80 00 00 00 be 28 52 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 b8 40 60 00 00 65 56 43 34 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

