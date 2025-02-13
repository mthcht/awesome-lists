rule TrojanDownloader_O97M_Gen_BB_2147741456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gen.BB!MTB"
        threat_id = "2147741456"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "svchst.exe" ascii //weight: 1
        $x_1_2 = {68 74 74 70 73 3a 2f 2f [0-64] 2f 73 76 63 68 73 74 2e 65 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

