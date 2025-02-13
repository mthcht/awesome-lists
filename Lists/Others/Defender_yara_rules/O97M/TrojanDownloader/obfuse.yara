rule TrojanDownloader_O97M_obfuse_DR_2147753289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/obfuse.DR!MTB"
        threat_id = "2147753289"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name" ascii //weight: 1
        $x_1_2 = "Sub malicious()" ascii //weight: 1
        $x_1_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 5c 5c 31 37 32 2e 31 36 2e 32 31 35 2e 31 33 31 5c [0-9] 5c 6b 61 70 69 74 61 6e 68 61 63 6b 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "Run Calculator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_obfuse_DR_2147753289_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/obfuse.DR!MTB"
        threat_id = "2147753289"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6c 62 39 6c 6d 74 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 36 2e 63 61 62 22 2c 00 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Attribute VB_Name" ascii //weight: 1
        $x_1_3 = ".run \"regsvr32 1.exp\"" ascii //weight: 1
        $x_1_4 = "Sub autoopen()" ascii //weight: 1
        $x_1_5 = "New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_obfuse_DR_2147753289_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/obfuse.DR!MTB"
        threat_id = "2147753289"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c 64 72 69 76 65 72 73 5c [0-15] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 ?? 2c 20 22 23 34 35 2e 37 38 2e 32 31 2e 31 35 30 20 [0-20] 22 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 65 6e 64 4b 65 79 73 20 22 25 28 [0-10] 29 7b 45 4e 54 45 52 7d 22}  //weight: 1, accuracy: Low
        $x_1_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 [0-15] 2e 78 6c 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_obfuse_DR_2147753289_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/obfuse.DR!MTB"
        threat_id = "2147753289"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tilpS.srahCiicsa$=mj$" ascii //weight: 1
        $x_1_2 = "37@A6@E2@F6@47@16@67@F2@13@13@13@E2@83@53@13@E2@73@23@23@E2@23@93@13@F2@F2@A3@07@47@47@86" ascii //weight: 1
        $x_1_3 = "92@72@37@A6@E2@F6@47@16@67@C5@72@02@B2@14@45@14@44@05@05@14@A3@67@E6@56@42@82@37@37@56@36@F6@27@07@D2@47@27@16@47@37" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

