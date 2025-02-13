rule VirTool_WinNT_Festeal_C_2147598187_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Festeal.C"
        threat_id = "2147598187"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Festeal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 75 02 eb 3d 0f b6 45 30 85 c0 74 0a b8 06 00 00 80 e9 bd 00 00 00 6a 00 6a 00 6a 01 8b 45 24 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 83 78 04 00 0f 84 87 00 00 00 68 ?? ?? 01 00 8b 45 0c 8b 48 04 51 e8 ?? ?? 00 00 83 c4 08 85 c0 75 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

