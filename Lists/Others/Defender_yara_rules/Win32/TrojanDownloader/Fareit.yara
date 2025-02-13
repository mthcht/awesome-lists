rule TrojanDownloader_Win32_Fareit_A_2147655426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fareit.A"
        threat_id = "2147655426"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fHdC71fuqSVe73Fh" ascii //weight: 1
        $x_1_2 = {0f be 08 33 f1 89 75 c4 8a 55 c4 88 55 dc 8a 45 dc 50 8d 4d b4}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 01 8b 45 e0 50 ff 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

