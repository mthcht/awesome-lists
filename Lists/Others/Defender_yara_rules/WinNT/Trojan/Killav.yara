rule Trojan_WinNT_Killav_BU_2147623066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.BU"
        threat_id = "2147623066"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e4 18 00 00 00 e8 ?? ?? 00 00 85 c0 7c 25 ff 75 08 ff 75 fc e8 ?? ?? 00 00 6a 00 ff 75 fc e8 ?? ?? 00 00 ff 75 fc 8b 35 ?? ?? 01 00 ff d6 ff 75 08 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {ab 8b 45 08 89 45 f4 8d 45 f4 50 8d 45 dc 50 68 ff 0f 1f 00 8d 45 fc 50 c7 45 dc 18 00 00 00 ff 15 ?? ?? 01 00 8b 45 fc 5f c9 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Killav_DK_2147626348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.DK"
        threat_id = "2147626348"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 0c 8b 4e 60 8b 41 0c 57 33 db 33 ff 3d 08 20 22 00 74 ?? 3d 4b 21 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {fa 50 0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_3 = {ec 53 56 57 b9 00 00 00 a0}  //weight: 1, accuracy: High
        $x_1_4 = {80 38 ff 75 11 80 78 01 75 75 0b 8a 50 02 3a 15 80 09 40 00 74 ?? 40 41 81 f9 96 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Killav_E_2147641117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.E"
        threat_id = "2147641117"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_2 = {14 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 08 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 0c 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 10 20 22 00 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {20 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 24 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 57 e1 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Killav_F_2147652314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.F"
        threat_id = "2147652314"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zwdeletefile" ascii //weight: 1
        $x_1_2 = "arquivo" ascii //weight: 1
        $x_1_3 = "avast" ascii //weight: 1
        $x_1_4 = {67 00 62 00 70 00 73 00 76 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 47 00 62 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_5_6 = {59 8b 45 08 c7 40 34 e0 02 01 00 68}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Killav_DL_2147678744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.DL"
        threat_id = "2147678744"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 e8 75 0b ?? 5d c2 00 00 66 39 ?? 05 74}  //weight: 1, accuracy: Low
        $x_1_2 = "PspTerminateThreadByPointer" ascii //weight: 1
        $x_1_3 = {00 00 61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 4e 00 56 00 43 00 41 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Killav_DM_2147679452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.DM"
        threat_id = "2147679452"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 e8 00 00 00 75 ?? 8b 55 ?? 0f b7 42 05 3d 5d c2 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = "PspTerminateThreadByPointer" ascii //weight: 1
        $x_1_3 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 00 56 00 43 00 41 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Killav_DN_2147691660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killav.DN"
        threat_id = "2147691660"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 38 e8 75 30 be 5d c2 00 00 66 39 70 05 75 25 8b 48 01}  //weight: 10, accuracy: High
        $x_10_2 = {80 38 e8 75 61 be c2 04 00 00 66 39 70 05 75 56 8b 48 01}  //weight: 10, accuracy: High
        $x_10_3 = {c7 45 fc fe ff ff ff 80 7d e7 01 8b 45 e0 74 04 0f b6 45 e7 e8}  //weight: 10, accuracy: High
        $x_10_4 = {80 38 e8 75 3a 66 81 78 05 5d c2 75 32 8b}  //weight: 10, accuracy: High
        $x_10_5 = {80 38 e8 0f 85 84 00 00 00 66 81 78 05 c2 04 75 7c 8b}  //weight: 10, accuracy: High
        $x_10_6 = "Search_PspTerminateThreadByPointer Error" ascii //weight: 10
        $x_1_7 = {41 00 59 00 55 00 50 00 44 00 53 00 52 00 56 00 2e 00 41 00 59 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 00 53 00 56 00 4d 00 4f 00 4e 00 2e 00 4e 00 50 00 43 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {4d 00 55 00 50 00 44 00 41 00 54 00 45 00 32 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 41 00 56 00 53 00 61 00 46 00 65 00 53 00 76 00 63 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

