rule TrojanDownloader_O97M_Damatak_A_2147722001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Damatak.A"
        threat_id = "2147722001"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Damatak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crate = allergy(ByVal transducer, ariston, ByVal oilseed, franctireur, ByVal reverential, ByVal component)" ascii //weight: 1
        $x_1_2 = "agaric = gelasmagr(ByVal diode, bowing, ByVal crossroad, fernlike, ByVal mh, ByVal melodramatically)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Damatak_B_2147723536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Damatak.B"
        threat_id = "2147723536"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Damatak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 [0-16] 4b 65 72 6e 65 6c 33 32 [0-16] 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 54 69 6d 65 72 51 75 65 75 65 54 69 6d 65 72 22}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 [0-16] 4e 74 64 6c 6c 2e 64 6c 6c [0-16] 22 20 41 6c 69 61 73 20 22 4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 22}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 [0-16] 4e 74 64 6c 6c 2e 64 6c 6c [0-16] 22 20 41 6c 69 61 73 20 [0-16] 22 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 22}  //weight: 1, accuracy: Low
        $x_1_4 = {23 49 66 20 [0-32] 57 69 6e 36 34}  //weight: 1, accuracy: Low
        $x_1_5 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

