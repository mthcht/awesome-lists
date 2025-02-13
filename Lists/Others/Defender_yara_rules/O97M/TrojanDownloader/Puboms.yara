rule TrojanDownloader_O97M_Puboms_2147729674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Puboms"
        threat_id = "2147729674"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Puboms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 [0-16] 20 2b 20 22 20 68 74 74 70 3a 2f 2f 6f 63 74 61 70 2e 69 67 67 2e 62 69 7a 2f 31 2f [0-16] 2e 6d 73 69 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "\"msiexec /q /i\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

