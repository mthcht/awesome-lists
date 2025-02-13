rule Trojan_WinNT_Stuxnet_B_2147635801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Stuxnet.B"
        threat_id = "2147635801"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 04 59 0f b7 04 4e 66 3d 30 00 72 c4 66 3d 39 00 77 be 0f b7 c0 8d 44 38 d0 6a 0a 99 5f f7 ff 41 83 f9 07 8b fa 7e db}  //weight: 3, accuracy: High
        $x_3_2 = {83 7d 0c 00 74 35 8b 45 08 0f b7 00 50 ff d3 0f b7 ce 51 89 45 fc ff d3 59 59 8b 4d fc 3b c1 75 1a 83 45 08 02 47 47 0f b7 37 ff 4d 0c 66 85 f6 75 ce}  //weight: 3, accuracy: High
        $x_1_3 = "{58763ECF-8AC3-4a5f-9430-1A310CE4BE0A}" ascii //weight: 1
        $x_1_4 = "\\FileSystem\\fastfat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Stuxnet_A_2147635802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Stuxnet.A"
        threat_id = "2147635802"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 34 19 3b f2 73 42 80 38 e8 75 0f 8b 70 01 8d 74 06 05 3b 35 ?? ?? ?? ?? 74 0e 41 48 83 f9 78 72 de}  //weight: 3, accuracy: Low
        $x_3_2 = {76 50 0f b7 c3 6b c0 28 8d 14 30 e8 ?? ?? ?? ff 84 c0 74 31 8b 42 08 8b 4a 10 3b c1 73 02}  //weight: 3, accuracy: Low
        $x_3_3 = {81 e6 00 f0 ff ff eb 06 81 ee 00 10 00 00 56 ff 74 24 0c e8 ?? 00 00 00 59 59 85 c0 75 [0-10] 56 8b 74 24 0c b8 4d 5a 00 00 66 39 06}  //weight: 3, accuracy: Low
        $x_3_4 = {a9 00 00 00 20 74 41 a8 20 74 3d a9 00 00 00 40 74 36 6a 08 59 bf ?? ?? ?? ?? 8b f2 33 c0 f3 a6}  //weight: 3, accuracy: Low
        $x_1_5 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 [0-8] 6e 74 6b 72 6e 6c 70 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 74 65 78 74 00 00 00 50 41 47 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

