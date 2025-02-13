rule Trojan_O97M_Vobfus_A_2147730644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Vobfus.A"
        threat_id = "2147730644"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-16] 22 2c 20}  //weight: 1, accuracy: Low
        $x_2_3 = {2d 20 52 6f 75 6e 64 28 [0-16] 20 2a 20 43 53 6e 67 28 [0-16] 20 2a 20 43 49 6e 74 28 [0-16] 29 29 20 2b 20 [0-16] 20 2d 20 52 6f 75 6e 64 28 [0-16] 29 29 20 2d 20 [0-16] 20 2f 20 43 69 4d 63 74 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_4 = {52 6e 64 28 [0-16] 29 20 2a 20 28 [0-16] 20 2f 20 43 44 62 6c 28 [0-16] 29 20 2b 20 28 [0-16] 20 2f 20 43 42 79 74 65 28 [0-16] 20 2f 20 43 44 62 6c 28 [0-16] 29 20 2d 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

