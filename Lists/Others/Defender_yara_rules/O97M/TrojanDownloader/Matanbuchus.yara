rule TrojanDownloader_O97M_Matanbuchus_PA_2147953192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Matanbuchus.PA!MTB"
        threat_id = "2147953192"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".InstallProduct" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"WindowsInstaller.Installer\")" ascii //weight: 1
        $x_3_3 = "bankruptcy-divorce.com/Bankruptcy/db.pak" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

