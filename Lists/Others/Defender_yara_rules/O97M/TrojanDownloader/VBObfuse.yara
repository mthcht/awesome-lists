rule TrojanDownloader_O97M_VBObfuse_AAET_2147898954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/VBObfuse.AAET"
        threat_id = "2147898954"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "VBObfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 62 36 39 32 66 36 35 37 38 36 31 36 64 32 66 [0-31] 32 65 36 35 37 38 36 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

