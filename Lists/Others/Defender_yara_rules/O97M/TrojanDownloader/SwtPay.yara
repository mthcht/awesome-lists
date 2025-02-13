rule TrojanDownloader_O97M_SwtPay_AA_2147742758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SwtPay.AA"
        threat_id = "2147742758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SwtPay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 28 [0-32] 94 68 74 74 70 3a 2f 2f 61 6c 6b 75 74 65 63 68 73 6c 6c 63 2e 63 6f 6d 2f [0-32] 2f [0-32] 2e 65 78 65 94}  //weight: 1, accuracy: Low
        $x_1_2 = {24 45 4e 76 3a 74 65 4d 70 5c [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {73 74 41 52 74 2d 50 52 6f 43 45 53 73 20 94 24 45 4e 76 3a 74 45 4d 50 5c [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

