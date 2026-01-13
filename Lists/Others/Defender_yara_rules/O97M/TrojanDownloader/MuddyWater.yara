rule TrojanDownloader_O97M_MuddyWater_GVA_2147960996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MuddyWater.GVA!MTB"
        threat_id = "2147960996"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "love_me__()" ascii //weight: 1
        $x_1_2 = "executor.Run instruction, 0, False" ascii //weight: 1
        $x_1_3 = "C:\\\\ProgramData\\\\CertificationKit.ini" ascii //weight: 1
        $x_1_4 = "MsgBox \"Hi, have a nice time :)\" & filePath" ascii //weight: 1
        $x_1_5 = "WriteHexToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

