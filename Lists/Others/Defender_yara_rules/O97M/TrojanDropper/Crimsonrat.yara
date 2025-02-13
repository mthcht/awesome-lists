rule TrojanDropper_O97M_Crimsonrat_RDO_2147826405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Crimsonrat.RDO!MTB"
        threat_id = "2147826405"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Crimsonrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 [0-95] 3d 65 6e 76 69 72 6f 6e 24 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 26 22 5c 6f 66 66 69 65 63 73 22 26 6d 69 6e 75 74 65 28 6e 6f 77 29 26 22 22 26 73 65 63 6f 6e 64 28 6e 6f 77 29 26 00 02 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 63 6f 70 79 66 69 6c 65 73 61 64 64 69 6e 73 2c 66 6f 6c 64 65 72 5f 61 64 6f 65 73 5f 6e 61 6d 65 26 22 64 61 74 61 2e 7a 69 70 22 2c 00 04 26 66 69 6c 65 5f 61 64 6f 65 73 5f 6e 61 6d 65 26 22 2e 65 22 26 72 65 70 6c 61 63 65 28 22 78 65 5f 70 61 22 2c 22 5f 70 61 22 2c 22 22 29 73 68 65 6c 6c 66 6f 6c 64 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

