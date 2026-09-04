rule TrojanDropper_O97M_RemcosRAT_SK_2147977553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/RemcosRAT.SK!MTB"
        threat_id = "2147977553"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-93] 2f [0-93] 2f [0-31] 2e 65 78 65 3f 65 78 3d [0-15] 26 69 73 3d [0-15] 26 68 6d 3d [0-79] 26}  //weight: 1, accuracy: Low
        $x_1_2 = "ad.SaveToFile LocalFilePath, 2 ' Overwrite" ascii //weight: 1
        $x_1_3 = {27 20 45 78 65 63 75 74 65 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 [0-10] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 4c 6f 63 61 6c 46 69 6c 65 50 61 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

