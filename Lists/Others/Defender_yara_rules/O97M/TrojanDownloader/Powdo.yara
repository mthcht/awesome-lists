rule TrojanDownloader_O97M_Powdo_YG_2147762986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdo.YG!MTB"
        threat_id = "2147762986"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curw.create \"rundll32 zipfldr.dll,RouteTheCall c:\\wordpress\\about1.vbs" ascii //weight: 1
        $x_1_2 = "n.CreateTextFile(\"c:\\wordpress\\about1.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

