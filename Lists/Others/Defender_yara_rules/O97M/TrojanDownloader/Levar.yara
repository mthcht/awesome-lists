rule TrojanDownloader_O97M_Levar_PV_2147765993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Levar.PV!MTB"
        threat_id = "2147765993"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Levar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 22 22 22 20 26 20 6d 61 6e 6e 65 72 ?? 20 26 20 22 5c 55 6e 72 61 76 65 6c 5c 6c 75 61 2e 63 6d 64}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Unravel\\bolt.lua" ascii //weight: 1
        $x_1_3 = "Kill manner4 + \"\\unravel.doc" ascii //weight: 1
        $x_1_4 = "UnStore manner4 + \"\\unravel.zip" ascii //weight: 1
        $x_1_5 = "= \"C:\\Users\" + \"\\Public" ascii //weight: 1
        $x_1_6 = "Call Shell(\"cmd /c copy \" + manner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

