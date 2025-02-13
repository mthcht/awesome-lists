rule TrojanDropper_O97M_Gyopej_A_2147697276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Gyopej.gen!A"
        threat_id = "2147697276"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gyopej"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-192] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 2c 20 22 [0-192] 22 29 29 20 26 20 22 5c 22 20 26 20 [0-192] 20 26 20 [0-192] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28}  //weight: 2, accuracy: Low
        $x_2_2 = {58 6f 72 20 28 [0-192] 28 28 [0-192] 28 [0-192] 29 20 2b 20 [0-192] 28 [0-192] 29 29 20 4d 6f 64 20 32 35 36 29 29}  //weight: 2, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-192] 28 [0-192] 28 22 [0-192] 22 29 2c 20 22 [0-192] 22 29 29 2e 65 78 65 63 20 22 22 22 22 20 26 20 [0-192] 20 26 20 22 22 22 22}  //weight: 1, accuracy: Low
        $x_1_4 = {28 53 74 72 43 6f 6e 76 28 [0-192] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 [0-192] 28 [0-192] 28 22 [0-192] 22 29 2c 20 22 [0-192] 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

