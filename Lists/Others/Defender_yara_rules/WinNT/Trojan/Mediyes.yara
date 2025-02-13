rule Trojan_WinNT_Mediyes_A_2147627881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Mediyes.A"
        threat_id = "2147627881"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d f8 8b 45 f4 c1 e1 02 8d 14 01 8b 02 8b 00 89 02 8b 55 f4 8b 0c 11 eb}  //weight: 10, accuracy: High
        $x_1_2 = {8b 45 0c 8b 4d 08 2b c8 83 e9 05 89 48 01 c6 00 e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 08 8b 4c 24 04 2b c8 83 e9 05 89 48 01 c6 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Mediyes_B_2147654758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Mediyes.B"
        threat_id = "2147654758"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d 08 2b c8 83 e9 05 89 48 01 c6 00 e9 83 c0 05 5d}  //weight: 1, accuracy: High
        $x_1_2 = {66 83 f9 46 75 a6 0f b7 48 0a 66 83 f9 6f 74 06 66 83 f9 4f 75 96 0f b7 48 0c 66 83 f9 78 74 06 66 83 f9 58 75 86 66 83 78 0e 2e 0f 85 7b ff ff ff 0f b7 48 10 66 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Mediyes_C_2147655196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Mediyes.C"
        threat_id = "2147655196"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 83 e9 05 c6 00 e9 89 48 01 83 c0 05}  //weight: 1, accuracy: High
        $x_1_2 = {fa 0f 20 c0 89 45 fc ?? 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {80 38 0e 0f 85 ?? ?? ?? ?? 8b 40 0c c7 43 1c 4c 08 00 00 b9 68 c0 22 00 3b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

