rule TrojanDownloader_O97M_Phoenix_BKO_2147811361_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Phoenix.BKO!MTB"
        threat_id = "2147811361"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Phoenix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 39 2e 35 39 2e 32 35 33 2f 63 75 74 2f [0-21] 2e 62 61 74 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Phoenix_RVA_2147811418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Phoenix.RVA!MTB"
        threat_id = "2147811418"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Phoenix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 39 2e 35 39 2e 32 35 33 2f 63 75 74 2f [0-25] 22 22 20 [0-16] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 35 31 2e 32 31 37 2e 31 31 33 2f 76 76 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

