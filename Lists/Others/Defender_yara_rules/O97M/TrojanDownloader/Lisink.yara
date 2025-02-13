rule TrojanDownloader_O97M_Lisink_A_2147742773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lisink.A"
        threat_id = "2147742773"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lisink"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 47 65 74 4c 6f 67 69 6e 28 [0-12] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 47 65 74 50 61 73 73 77 6f 72 64 28 [0-12] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Write bat" ascii //weight: 1
        $x_1_4 = ".Write vbs" ascii //weight: 1
        $x_1_5 = {53 68 65 6c 6c 20 28 [0-12] 28 41 72 72 61 79 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

