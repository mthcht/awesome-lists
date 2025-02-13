rule VirTool_WinNT_Wiessy_A_2147607518_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Wiessy.A"
        threat_id = "2147607518"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Wiessy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7c 05 e0 ff 75 07 80 7c 05 e1 15 74 08 40 83 f8 12 72 ec eb 4e}  //weight: 1, accuracy: High
        $x_1_2 = {74 7e 89 75 e4 8b 7d f4 6a 02 59 8d 75 e8 33 c0 f3 a7 74 1e}  //weight: 1, accuracy: High
        $x_1_3 = {eb 4b 8b 10 fa 0f 20 c0 25 ff ff fe ff}  //weight: 1, accuracy: High
        $x_1_4 = "\\??\\ipfill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Wiessy_B_2147607519_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Wiessy.B"
        threat_id = "2147607519"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Wiessy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 06 8b ff 55 8b c6 46 04 ec 0f 20 c0 0d 00 00 01 00}  //weight: 3, accuracy: High
        $x_3_2 = {75 47 e8 f2 fd ff ff 84 c0 0f 84 98 02 00 00 8d 45 e0}  //weight: 3, accuracy: High
        $x_2_3 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 00}  //weight: 2, accuracy: High
        $x_1_4 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 45 43 61 74 44 69 73 6b 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 44 65 76 69 63 65 5c 45 43 61 74 44 69 73 6b 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

