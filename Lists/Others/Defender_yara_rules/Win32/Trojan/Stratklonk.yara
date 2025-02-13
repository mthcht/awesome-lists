rule Trojan_Win32_Stratklonk_A_2147692363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stratklonk.A"
        threat_id = "2147692363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stratklonk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "loader-sys\\LoadsOriginais\\kac" wide //weight: 2
        $x_2_2 = {d2 00 c9 00 c5 00 ab 00 d5 00 d4 00 d5 00 d3 00 c8 00 c5 00 dd 00 d3 00 d4 00 d2 00 c5 00 cd 00}  //weight: 2, accuracy: High
        $x_2_3 = {cd 00 d8 00 dd 00 da 00 78 01 1c 20 dc 02 e1 00 dc 00 db 00 14 20 cc 00 ce 00 d2 00 cd 00 d9 00}  //weight: 2, accuracy: High
        $x_1_4 = {8b d0 8d 4d e4 ff d7 8b d0 8d 4b 4c ff d6 8d 45 e4 8d 4d e8 50 51 6a 02 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {8b 55 0c 8d 4d b8 0f bf c3 51 50 8b 02 c7 45 c0 01 00 00 00 50 c7 45 b8 02 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

