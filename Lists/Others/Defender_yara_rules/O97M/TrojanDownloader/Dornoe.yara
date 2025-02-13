rule TrojanDownloader_O97M_Dornoe_AC_2147739860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dornoe.AC"
        threat_id = "2147739860"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dornoe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoCorerct = Remark_1 + i02 + CopyChecker + i04 + Remss + LogoFirm + i07 + i08" ascii //weight: 1
        $x_1_2 = "Remark_1 = Cells(5, 1).Text" ascii //weight: 1
        $x_1_3 = "= Shell#(WqA, xlLookForBlanks)" ascii //weight: 1
        $x_1_4 = "Replace(Replace(Replace(check, \"#.a\", \"w\"), \",.y\", \"e\"), \"+.Z\", \"c\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

