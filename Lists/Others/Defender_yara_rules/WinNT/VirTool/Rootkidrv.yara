rule VirTool_WinNT_Rootkidrv_KG_2147618082_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkidrv.KG"
        threat_id = "2147618082"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkidrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 00 54 00 54 00 50 00 00 00 00 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 7b 00 35 00 44 00 34 00 32 00 34 00 33 00 34 00 45 00 2d 00 42 00 43 00 41 00 33 00 2d 00 34 00 30 00 36 00 31 00 2d 00 39 00 46 00 41 00 43 00 2d 00 43 00 33 00 41 00 42 00 45 00 45 00 30 00 42 00 38 00 32 00 45 00 43 00 7d 00 00 00 00 00 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 7b 00 35 00 44 00 34 00 32 00 34 00 33 00 34 00 45 00 2d 00 42 00 43 00 41 00 33 00 2d 00 34 00 30 00 36 00 31 00 2d 00 39 00 46 00 41 00 43 00 2d 00 43 00 33 00 41 00 42 00 45 00 45 00 30 00 42 00 38 00 32 00 45 00 43 00 7d 00 00 00 00 00 7b 35 44 34 32 34 33 34 45 2d 42 43 41 33 2d 34 30 36 31 2d 39 46 41 43 2d 43 33 41 42 45 45 30 42 38 32 45 43 7d}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 64 61 65 6d 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

