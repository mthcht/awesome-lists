rule TrojanDownloader_O97M_DownloadExec_PC_2147953193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DownloadExec.PC!MTB"
        threat_id = "2147953193"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DownloadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c [0-4] 22 [0-80] 70 6f 77 65 72 73 68 65 6c 6c [0-16] 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 [0-96] 27 2c 27 [0-64] 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 [0-64] 27 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_DownloadExec_PD_2147963541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DownloadExec.PD!MTB"
        threat_id = "2147963541"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DownloadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 2b 20 22 5c [0-16] 2d [0-8] 2d [0-8] 2d [0-8] 2d [0-21] 22 20 2b 20 22 2e 76 22 20 2b 20 22 62 22 20 2b 20 22 73 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 22 3c 21 44 4f 43 54 59 50 45 20 68 74 6d 6c 3e 3c 68 74 6d 6c 3e 3c 62 6f 64 79 20 6f 6e 6c 6f 61 64 3d 27 64 6f 63 75 6d 65 6e 74 2e 66 6f 72 6d 73 5b 30 5d 2e 73 75 62 6d 69 74 28 29 27 3e 3c 66 6f 72 6d 20 61 63 74 69 6f 6e 3d 27 68 74 74 70 73 3a 2f 2f 77 65 62 68 6f 6f 6b 2e 73 69 74 65 2f [0-16] 2d [0-8] 2d [0-8] 2d [0-8] 2d [0-21] 27 20 6d 65 74 68 6f 64 3d 27 70 6f 73 74 27 3e 3c 74 65 78 74 61 72 65 61 20 6e 61 6d 65 3d 27 77 33 72 65 76 69 65 77 27 3e}  //weight: 1, accuracy: Low
        $x_3_3 = {53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 22 20 2b 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 2b 20 22 5c [0-16] 2d [0-8] 2d [0-8] 2d [0-8] 2d [0-21] 22 20 2b 20 22 2e 76 22 20 2b 20 22 62 22 20 2b 20 22 73 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

