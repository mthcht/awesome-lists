rule TrojanDownloader_O97M_Lyantiq_A_2147742184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lyantiq.A"
        threat_id = "2147742184"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lyantiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://lovelyantiques.info/bin/inv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

