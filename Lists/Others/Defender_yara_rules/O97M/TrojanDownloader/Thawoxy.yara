rule TrojanDownloader_O97M_Thawoxy_A_2147688683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Thawoxy.A"
        threat_id = "2147688683"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Thawoxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_5 = ".FolderExists(hxa3h2y)) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

