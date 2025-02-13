rule VirTool_WinNT_Yellsob_A_2147608590_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Yellsob.A"
        threat_id = "2147608590"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Yellsob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 56 18 89 55 e4 8b 46 60 8b 48 0c 8b 58 10 8b 7e 3c 81 e9 23 e2 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 1a 6a 07 68 ?? ?? 01 00 ff b5 74 ff ff ff ff 15 ?? ?? 01 00 83 c4 0c 85 c0 75 07 b8 22 00 00 c0 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 8c d6 00 00 00 83 7d 24 03 0f 85 cc 00 00 00 83 65 24 00 56 57 33 c0 39 03 0f 94 c0 8b f8 8d 43 5e 50 8d 45 e8 50 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {6f 62 6a 66 72 65 5c 69 33 38 36 5c 4d 61 79 61 53 59 53 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

