rule TrojanDownloader_O97M_Wolfic_A_2147835296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Wolfic.A"
        threat_id = "2147835296"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Wolfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 55 6e 70 72 6f 74 65 63 74 [0-32] 28 22 64 72 61 67 6f 6e 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-64] 2e 43 61 70 74 69 6f 6e 20 26 20 [0-64] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Wolfic_B_2147835297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Wolfic.B"
        threat_id = "2147835297"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Wolfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alias \"CreateProcess\"" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-64] 2e 43 61 70 74 69 6f 6e 20 26 20 [0-64] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_3 = {22 68 74 74 70 73 3a 2f 2f [0-64] 2e 6c 6b 2f 64 2f [0-64] 62 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_4 = ".Status = 200 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Wolfic_C_2147835298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Wolfic.C"
        threat_id = "2147835298"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Wolfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alias \"CreateProcess\"" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-64] 2e 43 61 70 74 69 6f 6e 20 26 20 [0-64] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_3 = {22 68 74 74 70 73 3a 2f 2f [0-64] 2e [0-4] 2f 64 2f [0-64] 2f [0-64] 2e 70 6e 67 22}  //weight: 1, accuracy: Low
        $x_1_4 = ".Status = 200 Then" ascii //weight: 1
        $x_1_5 = {2e 4f 70 65 6e [0-64] 2e 43 61 70 74 69 6f 6e [0-64] 46 61 6c 73 65 [0-64] 2e 53 65 6e 64 [0-240] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

