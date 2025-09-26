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

