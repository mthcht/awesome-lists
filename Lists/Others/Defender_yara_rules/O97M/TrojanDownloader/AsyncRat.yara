rule TrojanDownloader_O97M_AsyncRAT_RV_2147911996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AsyncRAT.RV!MTB"
        threat_id = "2147911996"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://139.162.22.35/1.bat" ascii //weight: 1
        $x_1_2 = "callshell(strfile,vbnormalfocus)elseendifendsub" ascii //weight: 1
        $x_1_3 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

