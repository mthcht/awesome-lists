rule TrojanDownloader_O97M_Cridex_DHA_2147754554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Cridex.DHA!MTB"
        threat_id = "2147754554"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 6d 6f 63 2e [0-15] 2f 2f 3a 70 74 74 68 22 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "(StrReverse(\"pmet\")) & \"\\sn.tmp\"" ascii //weight: 1
        $x_10_3 = "(StrReverse(\"==wczV2YvJHUfJzMul2V6MHdtdWbul2d\"))" ascii //weight: 10
        $x_1_4 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 [0-5] 26 2c 20 53 74 72 52 65 76 65 72 73 65 28 [0-5] 29 2c}  //weight: 1, accuracy: Low
        $x_10_5 = {2e 43 72 65 61 74 65 20 [0-5] 2e [0-5] 28 29 20 2b 20 22 72 33 32 20 22 20 2b 20}  //weight: 10, accuracy: Low
        $x_10_6 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-5] 28 [0-5] 29 29}  //weight: 10, accuracy: Low
        $x_1_7 = "= StrReverse(\"vsger\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Cridex_DHB_2147755500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Cridex.DHB!MTB"
        threat_id = "2147755500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c 20 [0-48] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-48] 20 41 73 20 53 74 72 69 6e 67 2c 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = "\"URLDownloadToFileA\" (ByVal " ascii //weight: 1
        $x_1_3 = "= Environ" ascii //weight: 1
        $x_1_4 = "AppData = AppData & Chr(Asc(x) - 1)" ascii //weight: 1
        $x_1_5 = "= \"fadzjgdilazu\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

