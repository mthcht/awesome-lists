rule TrojanDownloader_O97M_TrickbotCrypt_SM_2147763959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickbotCrypt.SM!MTB"
        threat_id = "2147763959"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "CreateDirectoryA" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "http://borgernewsherald.com/AMPLinersOnline/lubiousindendets.dll" ascii //weight: 1
        $x_1_5 = "C:\\PerLog\\Help\\wsapx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickbotCrypt_SB_2147765384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB"
        threat_id = "2147765384"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "open\"c:\\programdata\\dot.jpeg" ascii //weight: 5
        $x_1_2 = "submoonlight()" ascii //weight: 1
        $x_1_3 = "worksheets(\"tableofcontent\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickbotCrypt_SB_2147765384_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickbotCrypt.SB!MTB"
        threat_id = "2147765384"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 63 72 65 61 74 65 74 65 78 74 66 69 6c 65 28 22 63 3a 5c [0-32] 5c [0-32] 2e 76 62 22 2b 22 73 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 63 72 65 61 74 65 66 6f 6c 64 65 72 28 22 63 3a 5c [0-32] 5c [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 65 78 65 63 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 63 3a 5c [0-32] 5c [0-32] 2e 76 62 22 2b 22 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

