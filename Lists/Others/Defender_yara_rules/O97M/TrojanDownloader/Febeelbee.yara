rule TrojanDownloader_O97M_Febeelbee_2147691840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Febeelbee"
        threat_id = "2147691840"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Febeelbee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bit.do/beebee11feb" ascii //weight: 1
        $x_1_2 = "\\somm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

