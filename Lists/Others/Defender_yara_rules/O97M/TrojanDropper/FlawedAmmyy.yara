rule TrojanDropper_O97M_FlawedAmmyy_A_2147743843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/FlawedAmmyy.A"
        threat_id = "2147743843"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FlawedAmmyy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 69 6c 6c 41 72 72 61 79 20 [0-16] 20 26 20 22 5c [0-32] 2e 62 69 6e 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= CreateObject(\"Shell.\" + \"Application\")" ascii //weight: 1
        $x_1_3 = {28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c [0-32] 2e 62 69 6e 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 65 77 56 61 6c 75 6a 65 20 [0-16] 20 2b 20 22 5c [0-32] 2e 22 20 2b 20 22 62 69 6e 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

