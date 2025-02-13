rule TrojanDownloader_O97M_NetWire_MK_2147755575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NetWire.MK!MSR"
        threat_id = "2147755575"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NetWire"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "load\"http://moonshine-mht.best/chrome.jpg\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

