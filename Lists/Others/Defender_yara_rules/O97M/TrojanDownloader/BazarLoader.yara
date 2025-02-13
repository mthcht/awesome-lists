rule TrojanDownloader_O97M_BazarLoader_R_2147787757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/BazarLoader.R!MTB"
        threat_id = "2147787757"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 22 2c 20 22 2f 63 20 22 20 26 20 [0-15] 2c 20 22 22 2c 20 22 22 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = " = CreateObject(\"shell.application\")" ascii //weight: 1
        $x_1_3 = "mx \"t\", \"\"" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-7] 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

