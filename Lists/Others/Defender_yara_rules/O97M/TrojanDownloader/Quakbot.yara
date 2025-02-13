rule TrojanDownloader_O97M_Quakbot_XL_2147765395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Quakbot.XL!MTB"
        threat_id = "2147765395"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Quakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://rangtreem.net/hhxjx/530340.png" ascii //weight: 1
        $x_1_2 = "http://rangtreem.net/hhxjx/Dm" ascii //weight: 1
        $x_1_3 = "zipfldr" ascii //weight: 1
        $x_1_4 = "C:\\Iopsd\\" ascii //weight: 1
        $x_1_5 = "JJCCCJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Quakbot_DAT_2147765527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Quakbot.DAT!MTB"
        threat_id = "2147765527"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Quakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://garosan.ir/xujpuomkaka" ascii //weight: 1
        $x_1_2 = "http://garosan.ir/xujpuomkaka/530340.png" ascii //weight: 1
        $x_1_3 = "C:\\Datop\\" ascii //weight: 1
        $x_1_4 = "zipfldr" ascii //weight: 1
        $x_1_5 = "JJCCCJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

