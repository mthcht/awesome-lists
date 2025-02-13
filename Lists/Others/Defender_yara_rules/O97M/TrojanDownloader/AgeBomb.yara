rule TrojanDownloader_O97M_AgeBomb_A_2147757945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AgeBomb.A!MTB"
        threat_id = "2147757945"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgeBomb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Open TXTFile For Output As #1" ascii //weight: 1
        $x_1_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 76 61 6c 20 28 [0-32] 2e 52 75 6e 28 50 61 74 68 20 2b 20 54 58 54 46 69 6c 65 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {50 61 74 68 20 3d 20 22 43 3a 5c 22 20 2b 20 [0-16] 70 61 74 68 20 2b 20 22 53 79 73 74 65 6d 33 32 5c 63 22 20 2b 20 22 73 63 72 69 70 74 22 20 2b 20 22 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"Scri\"" ascii //weight: 1
        $x_1_5 = "+ \"pti\"" ascii //weight: 1
        $x_1_6 = "= \"scr\" + \"ipt1\"" ascii //weight: 1
        $x_1_7 = "+ \".S\"" ascii //weight: 1
        $x_1_8 = "+ \"h\"" ascii //weight: 1
        $x_1_9 = "+ \"e\"" ascii //weight: 1
        $x_1_10 = "+ \"l\" & \"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

