rule Trojan_Win32_CrystalStruck_A_2147724722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrystalStruck.A!dha"
        threat_id = "2147724722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrystalStruck"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {9a cb bc fa 83 ?? 28 02 00 81}  //weight: 15, accuracy: Low
        $x_15_2 = {30 30 01 18 18 02 03 18 04 05 06 07 08 09 0a 0b 0c 18 18 18 0d 18 0e 0f 10 18 11 18 12 18 18 18 13 18 18 18 14 18 15 18 16 17}  //weight: 15, accuracy: High
        $x_5_3 = {68 86 34 43 05}  //weight: 5, accuracy: High
        $x_5_4 = {87 34 43 05 06 00 81}  //weight: 5, accuracy: Low
        $x_5_5 = {68 77 34 43 05}  //weight: 5, accuracy: High
        $x_5_6 = {68 64 34 43 05}  //weight: 5, accuracy: High
        $x_5_7 = {68 82 34 43 05}  //weight: 5, accuracy: High
        $x_10_8 = {77 77 77 2e 68 61 6e 63 6f 2e 63 6f 6d 2e 63 6e 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*))) or
            ((2 of ($x_15_*))) or
            (all of ($x*))
        )
}

