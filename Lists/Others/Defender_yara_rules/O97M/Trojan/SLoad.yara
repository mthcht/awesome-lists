rule Trojan_O97M_SLoad_RDA_2147900590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/SLoad.RDA!MTB"
        threat_id = "2147900590"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://www.herber.de/andere/bean.exe" ascii //weight: 2
        $x_2_2 = "Downl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

