rule TrojanDownloader_O97M_Powmet_A_2147720006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powmet.A"
        threat_id = "2147720006"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powmet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_10_2 = "Shell (\"powershell.exe \" &" ascii //weight: 10
        $x_10_3 = "\"-window hidden -e " ascii //weight: 10
        $x_10_4 = "cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlAC" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powmet_A_2147720006_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powmet.A"
        threat_id = "2147720006"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powmet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "Sub Auto_Open()" ascii //weight: 1
        $x_10_3 = "Shell (\"powershell.exe \" &" ascii //weight: 10
        $x_10_4 = "\"-window hidden -e " ascii //weight: 10
        $x_10_5 = "Function URLDownloadToFile Lib \"urlmon\" Alias \"URLDownloadToFileA\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

