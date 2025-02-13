rule Trojan_Linux_LateralMovement_B_2147808004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LateralMovement.B!Script"
        threat_id = "2147808004"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LateralMovement"
        severity = "Critical"
        info = "Script: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "235"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "ssh " wide //weight: 50
        $x_100_2 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 100, accuracy: Low
        $x_50_3 = "BatchMode" wide //weight: 50
        $x_25_4 = "curl " wide //weight: 25
        $x_25_5 = "wget " wide //weight: 25
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
            ((2 of ($x_50_*) and 2 of ($x_25_*) and 9 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_25_*) and 9 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 9 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_25_*) and 6 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_25_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_25_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_25_*))) or
            (all of ($x*))
        )
}

