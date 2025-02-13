rule TrojanDownloader_O97M_Filcave_A_2147696146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Filcave.A"
        threat_id = "2147696146"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Filcave"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TempLinkFinal = XorC(CalcFive, 1337) & TempColon & FuckTwo &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

