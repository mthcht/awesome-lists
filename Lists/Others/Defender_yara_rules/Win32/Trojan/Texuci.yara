rule Trojan_Win32_Texuci_B_2147687629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Texuci.B"
        threat_id = "2147687629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Texuci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "7ED03AA73A9EFD438ACF" ascii //weight: 2
        $x_2_2 = "1347B03CAE1572D761E4" ascii //weight: 2
        $x_2_3 = "23578EC217B3399934A826429635A63D9E23BA15B4" ascii //weight: 2
        $x_1_4 = "8CDC70D7084983878887DA76D3" ascii //weight: 1
        $x_2_5 = "1D41A1D61A40B0324693D10A5CFF5EE061F65A87EF68E77DDD64" ascii //weight: 2
        $x_2_6 = "38A5C9085FE26BFD4197C221BB2E91309233A82CB920B8164B8B" ascii //weight: 2
        $x_1_7 = "BC3390C0124F85E00779" ascii //weight: 1
        $x_1_8 = "1A6EED7ED10F45A0C437" ascii //weight: 1
        $x_1_9 = "E61DBA2DBE1A4EAB3040" ascii //weight: 1
        $x_1_10 = "88FC5A8ADD7BD12FB5C7" ascii //weight: 1
        $x_1_11 = "F254F85686C8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Texuci_C_2147687633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Texuci.C"
        threat_id = "2147687633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Texuci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "28B53896CD73DB0C4F85D02FA93C9F3E80DE74D9076FE969FC5DE56" ascii //weight: 2
        $x_2_2 = "FA0F469ACC096CEA67FD5D9B30AC3E923496CF0849" ascii //weight: 2
        $x_1_3 = "DD12B122B51349A4C83B" ascii //weight: 1
        $x_1_4 = "364A89DB0F4A9EDB0070" ascii //weight: 1
        $x_1_5 = "D72CAB3CAF2DA3DE0577" ascii //weight: 1
        $x_1_6 = "4DA323B529A43BB63D4F" ascii //weight: 1
        $x_1_7 = "E275E86EFE5EF61B7C9B31AC28" ascii //weight: 1
        $x_1_8 = "E67B84D10448478A3297" ascii //weight: 1
        $x_1_9 = "8EC0CB194DF313B61EA3" ascii //weight: 1
        $x_1_10 = "F76A95C015BBD87CC50B" ascii //weight: 1
        $x_1_11 = "4195FE6AF3177696FB" ascii //weight: 1
        $x_1_12 = "184AB5234A4D4C4CB1" ascii //weight: 1
        $x_1_13 = "5D9C33AB3C9FD40F4A9E28A03C99CB" ascii //weight: 1
        $x_1_14 = "CF22A53EAE1062E07EC3074782E66BE165" ascii //weight: 1
        $x_1_15 = "98EA6BE67ED274F16AEC5080" ascii //weight: 1
        $x_1_16 = "5B9F25B71BBE3D9D33993797" ascii //weight: 1
        $x_1_17 = "BE23A627A6D61C" ascii //weight: 1
        $x_1_18 = "798D31AB3CB4C8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

