rule TrojanDownloader_O97M_Ursinf_MK_2147754290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursinf.MK!MSR"
        threat_id = "2147754290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursinf"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "gp = zD.kT(\"tmp\") & \"\\HV.tmp\"" ascii //weight: 5
        $x_10_2 = "zD.y \"bac.9kon=l?php.p23i0oia/58ol02ew/moc.8fjjfbb//:ptth\", gp" ascii //weight: 10
        $x_2_3 = "U = URLDownloadToFile(0&, StrReverse(c5), EE, 0&, 0&)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

