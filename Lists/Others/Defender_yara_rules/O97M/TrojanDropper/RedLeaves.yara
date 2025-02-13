rule TrojanDropper_O97M_RedLeaves_A_2147730366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/RedLeaves.A!dha"
        threat_id = "2147730366"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nLen = ActiveDocument.Content.End" ascii //weight: 1
        $x_1_2 = "Set rContent = ActiveDocument.Range(1, nLen)" ascii //weight: 1
        $x_1_3 = "fs0.WriteLine (rContent)" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 25 74 65 6d 70 25 5c 5c [0-32] 2e 74 78 74 20 25 74 65 6d 70 25 5c 5c [0-32] 2e 63 61 62 20 26 26 65 78 70 61 6e 64 20 25 74 65 6d 70 25 5c 5c [0-32] 2e 63 61 62 20 2d 46 3a 2a 20 25 74 65 6d 70 25 5c 5c 26 26 25 74 65 6d 70 25 5c 5c [0-32] 22 2c 20 30 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 25 74 65 6d 70 25 5c 5c [0-32] 2e 74 78 74 20 2f 71 22 2c 20 30 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 25 74 65 6d 70 25 5c 5c [0-32] 2e 63 61 62 20 2f 71 22 2c 20 30 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

