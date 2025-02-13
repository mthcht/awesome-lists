rule TrojanDownloader_O97M_Bladabindi_2147697326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bladabindi"
        threat_id = "2147697326"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e = \"http://icbg-iq.com/Scripts/kinetics/droids/gangrini/upload/regzab.exe\"" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run (Replace(c, \"https://www.google.com/images/srpr/logo1w.png\", e)), 0, True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

