rule TrojanDownloader_O97M_JpgFetch_KA_2147742639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/JpgFetch.KA"
        threat_id = "2147742639"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JpgFetch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 [0-40] 2e 6a 70 67 27 2c 20 20 27 25 41 50 50 44 41 54 41 25 5c [0-30] 2e 65 78 65 27 29}  //weight: 2, accuracy: Low
        $x_2_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 [0-40] 2e 6a 70 67 27 2c 20 20 27 25 41 50 50 44 41 54 41 25 5c [0-30] 2e 6a 73 27 29}  //weight: 2, accuracy: Low
        $x_1_3 = "= Environ(\"APPDATA\") & \"\\\"" ascii //weight: 1
        $x_1_4 = {4f 70 65 6e 20 65 6e 76 20 26 20 22 [0-32] 22 20 26 20 22 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Attribute VB_Name = \"ModelsPage1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

