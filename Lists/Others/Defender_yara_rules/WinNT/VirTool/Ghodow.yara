rule VirTool_WinNT_Ghodow_A_2147632195_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Ghodow.A"
        threat_id = "2147632195"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Ghodow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3e 5c 00 3f 00 74 f3 a4 83 ef 02 80 3f 5c 74 05 c6 07 30 eb f3}  //weight: 2, accuracy: Low
        $x_1_2 = {66 81 3f c2 08 74 07 66 81 3f c2 10 75 ec 80 7f 02 00 75 e6 8d 59 50 81 c1 50 04 00 00 68 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 53 00 44 00 4e 00 5c 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 39 1d 00 00 c0 75 15 90 8b 4d 10 8b 91 b8 00 00 00 83 c2 02 89 91 b8 00 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Ghodow_B_2147632275_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Ghodow.B"
        threat_id = "2147632275"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Ghodow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 00 00 ff bf d1 e0 0f b6 88 d4 02 00 00 01 0d}  //weight: 1, accuracy: High
        $x_1_2 = {81 39 1d 00 00 c0 75 15 90 8b 4d 10 8b 91 b8 00 00 00 83 c2 02 89 91 b8 00 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

