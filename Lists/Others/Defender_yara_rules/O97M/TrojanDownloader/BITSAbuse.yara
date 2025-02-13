rule TrojanDownloader_O97M_BITSAbuse_B_2147734616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/BITSAbuse.B"
        threat_id = "2147734616"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 74 72 61 6e 73 66 65 72 [0-64] 2f 75 70 6c 6f 61 64}  //weight: 10, accuracy: Low
        $x_10_2 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 74 72 61 6e 73 66 65 72 [0-240] 68 74 74 70}  //weight: 10, accuracy: Low
        $x_10_3 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 64 6f 77 6e 6c 6f 61 64 [0-240] 68 74 74 70}  //weight: 10, accuracy: Low
        $x_10_4 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 61 64 64 66 69 6c 65 [0-240] 68 74 74 70}  //weight: 10, accuracy: Low
        $x_10_5 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 73 65 74 6e 6f 74 69 66 79 63 6d 64 6c 69 6e 65 [0-240] 68 74 74 70}  //weight: 10, accuracy: Low
        $x_10_6 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 73 65 74 6e 6f 74 69 66 79 63 6d 64 6c 69 6e 65 [0-240] 63 6d 64 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_7 = {62 69 74 73 61 64 6d 69 6e [0-16] 2f 73 65 74 6e 6f 74 69 66 79 63 6d 64 6c 69 6e 65 [0-240] 62 69 74 73 61 64 6d 69 6e}  //weight: 10, accuracy: Low
        $x_10_8 = {63 6f 70 79 [0-64] 5c 62 69 74 73 61 64 6d 69 6e 2e 65 78 65 [0-64] 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_BITSAbuse_C_2147734639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/BITSAbuse.C"
        threat_id = "2147734639"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bitsadmin" ascii //weight: 10
        $x_1_2 = "/transfer" ascii //weight: 1
        $x_1_3 = "/upload" ascii //weight: 1
        $x_1_4 = "/download" ascii //weight: 1
        $x_1_5 = "/addfile" ascii //weight: 1
        $x_1_6 = "/setnotifycmdline" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

