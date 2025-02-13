rule TrojanDownloader_O97M_Donfins_A_2147728577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donfins.A"
        threat_id = "2147728577"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donfins"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 [0-30] 20 26 20 [0-30] 20 26 20 [0-30] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #" ascii //weight: 1
        $x_1_3 = "Close #" ascii //weight: 1
        $x_1_4 = "For Output As #" ascii //weight: 1
        $x_1_5 = ".FreeSpace > 10000 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

