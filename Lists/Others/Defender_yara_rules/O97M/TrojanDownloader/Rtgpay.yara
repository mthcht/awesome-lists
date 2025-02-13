rule TrojanDownloader_O97M_Rtgpay_SB_2147742183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Rtgpay.SB"
        threat_id = "2147742183"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Rtgpay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.SGTR/mrof/moc.ruotycilop//:ptth" ascii //weight: 1
        $x_1_2 = "& StrReverse(\"exe.zwxrm3jo\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

