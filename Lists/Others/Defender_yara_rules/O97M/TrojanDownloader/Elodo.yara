rule TrojanDownloader_O97M_Elodo_YA_2147753658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Elodo.YA!MTB"
        threat_id = "2147753658"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Elodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Const HKEY_CURRENT_USER = &H80000001" ascii //weight: 1
        $x_1_2 = "GetObject(\"winmgmts:\\\\\" & strComputer" ascii //weight: 1
        $x_1_3 = "\\root\\default:StdRegProv" ascii //weight: 1
        $x_1_4 = {53 74 72 52 65 76 65 72 73 65 28 22 [0-21] 2f 79 6c 2e 74 69 62 5c 5c 3a 73 70 22 20 2b 20 22 74 22 20 2b 20 22 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

