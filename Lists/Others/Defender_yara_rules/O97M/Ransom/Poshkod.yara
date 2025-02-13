rule Ransom_O97M_Poshkod_A_2147686693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:O97M/Poshkod.gen!A"
        threat_id = "2147686693"
        type = "Ransom"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Poshkod"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 75 73 74 6f 6d 69 7a 61 62 6c 65 20 3d 20 54 72 75 65 0d 0a 50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a [0-16] 20 3d 20 22 4a 77 42}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 75 73 74 6f 6d 69 7a 61 62 6c 65 20 3d 20 54 72 75 65 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-16] 20 3d 20 22 4a 77 42}  //weight: 1, accuracy: Low
        $x_10_3 = {22 0d 0a 53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 00 2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 20 26 20 22 20 2d 6e 6f 65 78 69 74 20 2d 65 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64 20 22 20 26 20 [0-16] 2c 20 30 2c 20 46 61 6c 73 65 0d 0a 45 6e 64 20 53 75 62}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_O97M_Poshkod_B_2147687875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:O97M/Poshkod.gen!B"
        threat_id = "2147687875"
        type = "Ransom"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Poshkod"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJ" ascii //weight: 1
        $x_1_2 = "AGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAC" ascii //weight: 1
        $x_1_3 = "UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

