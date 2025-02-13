rule VirTool_WinNT_Xooba_A_2147645188_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Xooba.A"
        threat_id = "2147645188"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Xooba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 01 6a 07 6a 00 6a 00 8d ?? ?? ?? 50 8d ?? ?? ?? 50 68 81 00 00 00 8d ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c0 01 43 0c 8b 43 0c 33 d2 f7 35 ?? ?? ?? 00 8b c2 85 c0 76 0b}  //weight: 1, accuracy: Low
        $x_1_3 = "NTFS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

