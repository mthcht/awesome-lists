rule TrojanDownloader_O97M_Icedid_RS_2147768523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Icedid.RS!MTB"
        threat_id = "2147768523"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 22 20 2b 20 [0-16] 20 2b 20 22 65 6c 6c 22 29 2e 72 75 6e 28 [0-16] 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 56 42 41 2e 53 70 6c 69 74 28 [0-10] 28 22 6c 6d 74 68 2e 6e 69 7c 6d 6f 63 2e 6e 69 7c 65 78 65 2e 61 74 68 73 6d 22 29 2c 20 22 7c 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

