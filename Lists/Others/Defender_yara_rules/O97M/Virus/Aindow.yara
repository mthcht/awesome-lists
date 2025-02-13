rule Virus_O97M_Aindow_A_2147706830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Aindow.A"
        threat_id = "2147706830"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aindow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 [0-144] 2c 20 32 [0-2] 45 6e 64 20 46 75 6e 63 74 69 6f 6e 00 00 40 00 2e 77 72 69 74 65 20 40 00 2e 4f 70 65 6e 40 00 2e 54 79 70 65 20 3d 20 31 80 00 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 39 37 29 20}  //weight: 5, accuracy: Low
        $x_1_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 [0-144] 2c 20 32 [0-2] 45 6e 64 20 46 75 6e 63 74 69 6f 6e 00 00 40 00 2e 77 72 69 74 65 20 40 00 2e 4f 70 65 6e 40 00 2e 54 79 70 65 20 3d 20 31 40 00 20 26 20 43 68 72 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

