rule Trojan_Linux_SuspiciousPersistence_B_2147808089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspiciousPersistence.B!Crontab"
        threat_id = "2147808089"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspiciousPersistence"
        severity = "Critical"
        info = "Crontab: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = "curl " wide //weight: 30
        $x_30_2 = "wget " wide //weight: 30
        $x_20_3 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 20, accuracy: Low
        $x_50_4 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 [0-6] 2f 00}  //weight: 50, accuracy: Low
        $x_50_5 = ".tor2web.su/" wide //weight: 50
        $x_10_6 = "|sh" wide //weight: 10
        $x_10_7 = "| sh" wide //weight: 10
        $x_10_8 = "|bash" wide //weight: 10
        $x_10_9 = "| bash" wide //weight: 10
        $x_10_10 = "|dash" wide //weight: 10
        $x_10_11 = "| dash" wide //weight: 10
        $x_10_12 = "|csh" wide //weight: 10
        $x_10_13 = "| csh" wide //weight: 10
        $x_10_14 = "|zsh" wide //weight: 10
        $x_10_15 = "| zsh" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 9 of ($x_10_*))) or
            ((1 of ($x_30_*) and 8 of ($x_10_*))) or
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 6 of ($x_10_*))) or
            ((2 of ($x_30_*) and 5 of ($x_10_*))) or
            ((2 of ($x_30_*) and 1 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_50_*) and 6 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 3 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

