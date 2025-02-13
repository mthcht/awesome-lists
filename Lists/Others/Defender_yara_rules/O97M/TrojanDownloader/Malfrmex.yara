rule TrojanDownloader_O97M_Malfrmex_A_2147740368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malfrmex.A"
        threat_id = "2147740368"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malfrmex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".savetofile \"all.e\" & \"xe\", 2" ascii //weight: 2
        $x_1_2 = "ExecuteExcel4Macro \"MESSAGE(True, \"\"release\"\")\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Malfrmex_B_2147740480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malfrmex.B"
        threat_id = "2147740480"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malfrmex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "time = Format(Now + TimeSerial(0, 0, 24), \"hh:mm\")" ascii //weight: 1
        $x_1_2 = "Shell Replace(App2.T3.Text, \"77:77\", time)" ascii //weight: 1
        $x_1_3 = "Unload Me" ascii //weight: 1
        $x_1_4 = "CallByName App1, \"Show\", VbMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

