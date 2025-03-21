rule TrojanDownloader_O97M_Iseriste_A_2147721899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Iseriste.A"
        threat_id = "2147721899"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Iseriste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"Process '%TMP%\\terorist.exe';\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

