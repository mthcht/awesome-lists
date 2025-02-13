rule TrojanDownloader_O97M_MsiexecAbuse_B_2147735593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MsiexecAbuse.B"
        threat_id = "2147735593"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MsiexecAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {6d 73 69 65 78 65 63 [0-48] 68 74 74 70}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

