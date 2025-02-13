rule TrojanDownloader_O97M_NJRat_RV_2147775172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NJRat.RV!MTB"
        threat_id = "2147775172"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 1
        $x_1_2 = "f = xsadwqdwqd(YxJkWXKoGpMPRTj)" ascii //weight: 1
        $x_1_3 = "Shell f" ascii //weight: 1
        $x_1_4 = "sadsad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_NJRat_RVA_2147775383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NJRat.RVA!MTB"
        threat_id = "2147775383"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 1
        $x_1_2 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Shell f" ascii //weight: 1
        $x_1_4 = "sadsad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_NJRat_BK_2147775408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NJRat.BK!MTB"
        threat_id = "2147775408"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 [0-15] 2c 20 69 2c 20 32 29 29 20 2d 20 31 33 29}  //weight: 1, accuracy: Low
        $x_1_2 = {69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-15] 29 20 53 74 65 70 20 32}  //weight: 1, accuracy: Low
        $x_1_3 = "Shell f" ascii //weight: 1
        $x_1_4 = "Sub sadsad()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_NJRat_BK_2147775408_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NJRat.BK!MTB"
        threat_id = "2147775408"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_2 = "WQDWQEWQEWQ.Run asd" ascii //weight: 1
        $x_1_3 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 1
        $x_1_4 = "Sub sadsad()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

