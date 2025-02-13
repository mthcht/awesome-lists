rule TrojanDownloader_O97M_Onchro_A_2147730355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Onchro.A"
        threat_id = "2147730355"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Onchro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s = Base64Decode(\"aHR0cDovLzEwMy4yNTUuMTAxLjY0L35vbjljaG9w" ascii //weight: 1
        $x_1_2 = "s1 = oShell.expandenvironmentstrings(\"%Temp%\") & \"\\chrome.exe\"" ascii //weight: 1
        $x_1_3 = "oShell.Run (s1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

