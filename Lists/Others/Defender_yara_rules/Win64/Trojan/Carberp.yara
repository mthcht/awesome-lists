rule Trojan_Win64_Carberp_A_2147682247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Carberp.A"
        threat_id = "2147682247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 78 fe 36 75 06 48 83 c0 fe eb (09 66 c7 00|0b c6 00 36 c6 40) 48 83 c0 02 48 8d 15 ?? ?? ?? ?? 48 8b cb c6 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 44 24 20 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 43 28 (ba 64 86|66 ba) 48 8d 8b c0 00 00 00 8b f8 48 8d 83 d0 00 00 00 48 03 fe 66 39 53 04 48 0f 44 c8 83 39 00 74}  //weight: 2, accuracy: Low
        $x_1_3 = "D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)" ascii //weight: 1
        $x_1_4 = {52 46 42 20 30 30 33 2e 30 30 38 0a}  //weight: 1, accuracy: High
        $x_1_5 = {56 6e 63 44 4c 4c 2e 64 6c 6c 00 56 6e 63 53 72 76 57 6e 64 50 72 6f 63 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

