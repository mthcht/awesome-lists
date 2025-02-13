rule TrojanDownloader_O97M_Kriof_A_2147706149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Kriof.A"
        threat_id = "2147706149"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kriof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-window hidden -enc" ascii //weight: 1
        $x_1_2 = "Critical Microsoft Office Error" ascii //weight: 1
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_5 = "JAAxACAAPQAgACcAJABjACAAPQAgAC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

