rule TrojanDownloader_O97M_SmkLdr_V_2147753820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SmkLdr.V!MTB"
        threat_id = "2147753820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SmkLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WScript.Shell" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 34 35 2e 31 34 37 2e 32 33 31 2e [0-4] 2f 6c 64 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "c:\\Atta5\\ldr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

