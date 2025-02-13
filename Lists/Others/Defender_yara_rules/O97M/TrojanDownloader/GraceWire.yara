rule TrojanDownloader_O97M_GraceWire_JK_2147757570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/GraceWire.JK!MTB"
        threat_id = "2147757570"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://requestbin.net/r/163xiqa1" ascii //weight: 1
        $x_1_2 = "powershell -Command \"\"(new-object net.webclient).DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

