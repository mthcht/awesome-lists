rule TrojanDownloader_O97M_Powload_GG_2147759784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powload.GG!MTB"
        threat_id = "2147759784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 [0-2] 53 68 65 6c 6c 20 [0-75] 28 22 31 32 33 32 32 33 34 32 31 33 32 22 2c 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-75] 28 43 6f 64 65 4b 65 79 20 41 73 20 53 74 72 69 6e 67 2c 20 73 74 72 20 41 73 20 53 74 72 69 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_3 = "For i = 1 To Len(str) Step 2" ascii //weight: 1
        $x_1_4 = {73 53 74 72 20 3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 73 74 72 2c 20 69 2c 20 ?? 29 29 20 2d 20 ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_5 = "sStr = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

